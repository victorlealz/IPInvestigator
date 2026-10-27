@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
  set PYTHON=py
) else (
  set PYTHON=python
)

if not exist ".venv\Scripts\python.exe" (
  echo [IP Investigator] Criando ambiente virtual...
  %PYTHON% -m venv .venv
)

call .venv\Scripts\activate.bat
python -m pip install --disable-pip-version-check -q -r requirements.txt

echo [IP Investigator] Iniciando interface local...
python -m streamlit run app.py
endlocal
