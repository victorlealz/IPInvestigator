from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "packaging" / "windows" / "ip_investigator.spec"
SPEC_DIR = SPEC.parent


def test_spec_anchors_paths_to_pyinstaller_specpath():
    text = SPEC.read_text(encoding="utf-8")
    assert "SPEC_DIR = Path(SPECPATH).resolve()" in text
    assert "ROOT = SPEC_DIR.parent.parent" in text
    assert '[str((SPEC_DIR / "standalone_launcher.py").resolve())]' in text
    assert '"packaging/windows/standalone_launcher.py"' not in text
    assert (SPEC_DIR / "standalone_launcher.py").is_file()


def test_spec_declares_all_required_project_data():
    expected = (
        "app.py",
        "core",
        "assets",
        ".streamlit",
        ".env.example",
        "THIRD_PARTY_NOTICES.md",
        "VERSION",
    )
    text = SPEC.read_text(encoding="utf-8")
    for relative in expected:
        assert f'src("{relative}")' in text
        assert (ROOT / relative).exists()


def test_build_script_invokes_spec_by_absolute_root_path():
    script = (SPEC_DIR / "build_windows.ps1").read_text(encoding="utf-8-sig")
    assert '$Spec = Join-Path $Root "packaging\\windows\\ip_investigator.spec"' in script
    assert '$Launcher = Join-Path $Root "packaging\\windows\\standalone_launcher.py"' in script
    assert '& $VenvPython -m PyInstaller --noconfirm --clean $Spec' in script
