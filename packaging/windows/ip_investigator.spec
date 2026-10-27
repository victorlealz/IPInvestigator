# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_submodules, copy_metadata

block_cipher = None

# SPECPATH is provided by PyInstaller while executing a .spec file. Build every
# source path from it so the build is independent from the shell's current
# directory and cannot accidentally duplicate "packaging/windows".
SPEC_DIR = Path(SPECPATH).resolve()
ROOT = SPEC_DIR.parent.parent


def src(relative: str) -> str:
    return str((ROOT / relative).resolve())


datas = [
    (src("app.py"), "."),
    (src("core"), "core"),
    (src("assets"), "assets"),
    (src(".streamlit"), ".streamlit"),
    (src(".env.example"), "."),
    (src("THIRD_PARTY_NOTICES.md"), "."),
    (src("VERSION"), "."),
]
binaries = []

# app.py is data, not an Analysis entry script. Therefore its imports must be made
# explicit here, otherwise a build can succeed but fail only after Streamlit loads app.py.
hiddenimports = []
hiddenimports += collect_submodules("core")
hiddenimports += collect_submodules("dotenv")

# These packages rely on dynamic imports and/or package data.
for package in ("streamlit", "reportlab", "tzdata"):
    d, b, h = collect_all(package)
    datas += d
    binaries += b
    hiddenimports += h

# Metadata is used by importlib.metadata at runtime by Streamlit and dependencies.
for dist in (
    "streamlit",
    "reportlab",
    "requests",
    "python-dotenv",
    "tzdata",
    "certifi",
    "urllib3",
    "idna",
    "charset-normalizer",
):
    try:
        datas += copy_metadata(dist, recursive=True)
    except Exception:
        pass

hiddenimports = list(dict.fromkeys(hiddenimports))


a = Analysis(
    [str((SPEC_DIR / "standalone_launcher.py").resolve())],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="IP-Investigator",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # UPX can increase AV false positives and break native wheels. Reliability wins.
    upx=False,
    console=False,
    disable_windowed_traceback=True,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
