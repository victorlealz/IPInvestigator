[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$SkipSmokeTest,
    [switch]$KeepBuildEnvironment
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Get-BuildPython {
    $candidates = @(
        @{ Command = "py"; Args = @("-3.14") },
        @{ Command = "py"; Args = @("-3.13") },
        @{ Command = "py"; Args = @("-3.12") },
        @{ Command = "python"; Args = @() }
    )

    foreach ($candidate in $candidates) {
        try {
            $cmd = Get-Command $candidate.Command -ErrorAction Stop
            & $cmd.Source @($candidate.Args) -c "import sys; assert sys.version_info >= (3,12); print(sys.executable)" *> $null
            if ($LASTEXITCODE -eq 0) {
                return @($cmd.Source) + @($candidate.Args)
            }
        } catch {
            continue
        }
    }

    throw "Python 3.12 ou superior não foi encontrado. Instale Python x64 apenas na máquina de BUILD; o executável final não precisará dele."
}

$BuildPython = Get-BuildPython
$Venv = Join-Path $Root ".build-venv"
$VenvPython = Join-Path $Venv "Scripts\python.exe"

$baseExe = $BuildPython[0]
$baseArgs = @()
if ($BuildPython.Count -gt 1) { $baseArgs = $BuildPython[1..($BuildPython.Count - 1)] }
$PyArch = (& $baseExe @baseArgs -c "import platform,struct; print(platform.machine()); print(struct.calcsize('P')*8)")
if ($LASTEXITCODE -ne 0) { throw "Não foi possível validar a arquitetura do Python de build." }
if ($PyArch.Count -lt 2 -or $PyArch[1].Trim() -ne "64") {
    throw "Use Python 64-bit para gerar o executável Windows x64."
}

Write-Step "Criando ambiente isolado de build"
if (Test-Path $Venv) {
    Remove-Item $Venv -Recurse -Force
}

& $baseExe @baseArgs -m venv $Venv
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $VenvPython)) {
    throw "Não foi possível criar o ambiente de build."
}

try {
    Write-Step "Instalando dependências de build"
    & $VenvPython -m pip install --disable-pip-version-check --upgrade pip setuptools wheel
    if ($LASTEXITCODE -ne 0) { throw "Falha ao atualizar pip/setuptools/wheel." }

    & $VenvPython -m pip install --disable-pip-version-check -r requirements.txt -r requirements-dev.txt "pyinstaller>=6.11,<7"
    if ($LASTEXITCODE -ne 0) { throw "Falha ao instalar dependências." }

    Write-Step "Validando imports críticos"
    & $VenvPython -c "import streamlit, requests, dotenv, reportlab, tzdata; from core.investigator import investigate_ip; print('Imports OK')"
    if ($LASTEXITCODE -ne 0) { throw "Validação de imports falhou." }

    if (-not $SkipTests) {
        Write-Step "Executando testes"
        & $VenvPython -m pytest -q
        if ($LASTEXITCODE -ne 0) { throw "Os testes falharam; o EXE não será gerado." }
    }

    Write-Step "Gerando executável Windows x64 standalone"
    Remove-Item (Join-Path $Root "build") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $Root "dist") -Recurse -Force -ErrorAction SilentlyContinue

    $Spec = Join-Path $Root "packaging\windows\ip_investigator.spec"
    $Launcher = Join-Path $Root "packaging\windows\standalone_launcher.py"
    if (-not (Test-Path $Spec)) { throw "Arquivo .spec não encontrado: $Spec" }
    if (-not (Test-Path $Launcher)) { throw "Launcher não encontrado: $Launcher" }

    & $VenvPython -m PyInstaller --noconfirm --clean $Spec
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller falhou." }

    $Exe = Join-Path $Root "dist\IP-Investigator.exe"
    if (-not (Test-Path $Exe)) {
        throw "O executável não foi gerado."
    }

    Write-Step "Validando artefato"
    $bytes = [System.IO.File]::ReadAllBytes($Exe)
    if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
        throw "O arquivo gerado não possui cabeçalho PE/MZ válido."
    }
    if ((Get-Item $Exe).Length -lt 5MB) {
        throw "O executável ficou pequeno demais; provável build incompleto."
    }

    $Hash = (Get-FileHash $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
    "$Hash  IP-Investigator.exe" | Set-Content (Join-Path $Root "dist\IP-Investigator.exe.sha256") -Encoding ASCII

    $Zip = Join-Path $Root "dist\IP-Investigator-Windows-x64.zip"
    Compress-Archive -Path $Exe,(Join-Path $Root "dist\IP-Investigator.exe.sha256") -DestinationPath $Zip -Force

    if (-not $SkipSmokeTest) {
        Write-Step "Executando smoke test do EXE gerado"
        $SmokePort = $null
        foreach ($candidate in 8599..8501) {
            $listener = $null
            try {
                $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $candidate)
                $listener.Start()
                $SmokePort = $candidate
                break
            } catch {
                continue
            } finally {
                if ($null -ne $listener) { $listener.Stop() }
            }
        }
        if ($null -eq $SmokePort) { throw "Nenhuma porta disponível para o smoke test." }

        $oldPort = $env:IP_INVESTIGATOR_PORT
        $env:IP_INVESTIGATOR_PORT = [string]$SmokePort
        $proc = $null
        try {
            $proc = Start-Process -FilePath $Exe -PassThru
            $healthUrl = "http://127.0.0.1:$SmokePort/_stcore/health"
            $deadline = [DateTime]::UtcNow.AddSeconds(75)
            $healthy = $false
            while ([DateTime]::UtcNow -lt $deadline) {
                if ($proc.HasExited) {
                    throw "O EXE encerrou durante o smoke test com código $($proc.ExitCode)."
                }
                try {
                    $resp = Invoke-WebRequest -UseBasicParsing -Uri $healthUrl -TimeoutSec 2
                    if ($resp.StatusCode -eq 200) {
                        $healthy = $true
                        break
                    }
                } catch {
                    Start-Sleep -Milliseconds 500
                }
            }
            if (-not $healthy) { throw "O EXE não respondeu ao health check em $healthUrl." }
            Write-Host "Smoke test OK: $healthUrl" -ForegroundColor Green
        } finally {
            if ($null -ne $proc -and -not $proc.HasExited) {
                & taskkill.exe /PID $proc.Id /T /F *> $null
            }
            $env:IP_INVESTIGATOR_PORT = $oldPort
        }
    }

    Write-Host ""
    Write-Host "Build concluído com sucesso." -ForegroundColor Green
    Write-Host "EXE: $Exe"
    Write-Host "ZIP: $Zip"
    Write-Host "SHA-256: $Hash"
    Write-Host "Dados em execução: %LOCALAPPDATA%\IP Investigator"
    Write-Host "O EXE final não instala Python nem executa pip na máquina do usuário."
}
finally {
    if (-not $KeepBuildEnvironment -and (Test-Path $Venv)) {
        Write-Step "Removendo ambiente temporário de build"
        Remove-Item $Venv -Recurse -Force -ErrorAction SilentlyContinue
    }
}
