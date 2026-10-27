#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if [ ! -x ".venv/bin/python" ]; then
  echo "[IP Investigator] Criando ambiente virtual..."
  "$PYTHON_BIN" -m venv .venv
fi

. .venv/bin/activate
python -m pip install --disable-pip-version-check -q -r requirements.txt

echo "[IP Investigator] Iniciando interface local..."
python -m streamlit run app.py
