# Windows EXE standalone

A distribuição recomendada é um único `IP-Investigator.exe` gerado pelo PyInstaller em um **Windows 64-bit**.

O executável final:

- inclui o interpretador Python e as dependências;
- **não instala Python** na máquina do usuário;
- **não executa `pip`** na primeira abertura;
- não baixa dependências para iniciar;
- inicia o Streamlit apenas em `127.0.0.1`;
- abre a interface no navegador padrão;
- grava banco e logs fora do executável, em `%LOCALAPPDATA%\IP Investigator`;
- usa uma faixa de portas locais de `8501` a `8599` para evitar conflito com outra instância;
- inclui `tzdata`, recursos do Streamlit, ReportLab e Cytoscape.js no pacote.

## Gerar o EXE no Windows

Dê dois cliques em:

```text
BUILD-WINDOWS-STANDALONE.cmd
```

ou execute:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File packaging\windows\build_windows.ps1
```

O processo cria um ambiente isolado somente para compilação, instala as dependências de build, valida imports, executa os testes, gera o executável e faz um **smoke test real**: abre o EXE, consulta `/_stcore/health` em localhost e só conclui se houver resposta HTTP 200.

Ao final, gera:

```text
dist\IP-Investigator.exe
dist\IP-Investigator.exe.sha256
dist\IP-Investigator-Windows-x64.zip
```

O ambiente temporário `.build-venv` é removido ao final.

## Requisito apenas da máquina de build

É necessário Python 64-bit 3.12 ou superior **somente para gerar** o executável. O computador que irá usar `IP-Investigator.exe` não precisa ter Python instalado.

## Dados e logs em execução

```text
%LOCALAPPDATA%\IP Investigator\data\ip_investigator.db
%LOCALAPPDATA%\IP Investigator\logs\launcher.log
```

Se `%LOCALAPPDATA%` não estiver disponível ou não for gravável, o inicializador tenta `%APPDATA%`, `%TEMP%` e, por último, a pasta de usuário.

## Chaves opcionais

Um `.env` colocado ao lado de `IP-Investigator.exe` pode conter as chaves opcionais:

```env
ABUSEIPDB_API_KEY=
GREYNOISE_API_KEY=
IPINFO_TOKEN=
```

## Correções específicas do standalone

- `app.py` é executado pelo Streamlit como arquivo e, por isso, seus imports não são descobertos automaticamente pelo PyInstaller. O `.spec` inclui explicitamente `dotenv` e os módulos `core`.
- Pacotes com recursos/imports dinâmicos (`streamlit`, `reportlab`, `tzdata`) são coletados explicitamente.
- O launcher valida a existência de `app.py`, `core`, configuração do Streamlit e Cytoscape antes de iniciar.
- O diretório de dados é testado quanto a escrita antes de ser usado.
- O file watcher do Streamlit fica desativado em produção.
- UPX fica desativado para reduzir falsos positivos de antivírus e problemas com bibliotecas nativas.
- O build valida o cabeçalho PE/MZ e recusa artefatos anormalmente pequenos.

## GitHub Actions

O workflow `.github/workflows/build-windows-exe.yml` executa o mesmo build em `windows-latest` e publica os artefatos do Windows.
