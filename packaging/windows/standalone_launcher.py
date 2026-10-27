from __future__ import annotations

import ctypes
import logging
import os
import socket
import sys
import tempfile
import threading
import time
import traceback
import urllib.request
import webbrowser
from pathlib import Path

APP_NAME = "IP Investigator"
PORT_START = 8501
PORT_END = 8599
HEALTH_TIMEOUT_SECONDS = 60.0


def _bundle_root() -> Path:
    """Return the directory that contains resources bundled by PyInstaller."""
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        return Path(frozen_root)
    return Path(__file__).resolve().parents[2]


def _candidate_user_roots() -> list[Path]:
    candidates: list[Path] = []
    for env_name in ("LOCALAPPDATA", "APPDATA"):
        value = os.environ.get(env_name)
        if value:
            candidates.append(Path(value) / APP_NAME)
    candidates.append(Path(tempfile.gettempdir()) / APP_NAME)
    candidates.append(Path.home() / ".ip-investigator")

    unique: list[Path] = []
    seen: set[str] = set()
    for item in candidates:
        key = str(item).casefold()
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _user_root() -> Path:
    """Create writable per-user storage, with fallbacks for restricted Windows profiles."""
    failures: list[str] = []
    for root in _candidate_user_roots():
        try:
            for child in ("data", "logs", "tmp"):
                (root / child).mkdir(parents=True, exist_ok=True)
            probe = root / "tmp" / ".write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return root
        except OSError as exc:
            failures.append(f"{root}: {exc}")
    raise RuntimeError(
        "Não foi possível criar uma pasta gravável para os dados do aplicativo. "
        + " | ".join(failures)
    )


def _setup_logging(root: Path) -> Path:
    log_path = root / "logs" / "launcher.log"
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
        force=True,
    )
    return log_path


def _show_error(message: str, log_path: Path | None = None) -> None:
    detail = message
    if log_path:
        detail += f"\n\nLog de diagnóstico:\n{log_path}"
    try:
        ctypes.windll.user32.MessageBoxW(0, detail, APP_NAME, 0x10)
    except Exception:
        sys.stderr.write(detail + "\n")


def _port_is_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


def _available_port() -> int:
    requested = os.environ.get("IP_INVESTIGATOR_PORT", "").strip()
    if requested:
        try:
            port = int(requested)
        except ValueError as exc:
            raise RuntimeError("IP_INVESTIGATOR_PORT deve ser um número inteiro.") from exc
        if not (1 <= port <= 65535):
            raise RuntimeError("IP_INVESTIGATOR_PORT deve estar entre 1 e 65535.")
        if not _port_is_available(port):
            raise RuntimeError(f"A porta local solicitada {port} já está em uso.")
        return port

    for port in range(PORT_START, PORT_END + 1):
        if _port_is_available(port):
            return port
    raise RuntimeError(
        f"Nenhuma porta local livre entre {PORT_START} e {PORT_END}. "
        "Feche outras instâncias do aplicativo e tente novamente."
    )


def _wait_and_open(url: str, timeout_seconds: float = HEALTH_TIMEOUT_SECONDS) -> None:
    health = f"{url}/_stcore/health"
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(health, timeout=1) as response:
                if response.status == 200:
                    opened = webbrowser.open(url, new=2)
                    logging.info("Interface pronta em %s; browser_open=%s", url, opened)
                    return
        except Exception as exc:  # health check is intentionally tolerant while booting
            last_error = exc
        time.sleep(0.25)
    logging.warning(
        "Servidor não respondeu ao health check em %.1fs. Último erro: %r",
        timeout_seconds,
        last_error,
    )


def _configure_environment(bundle: Path, user_root: Path) -> None:
    os.environ["IP_INVESTIGATOR_DB_PATH"] = str(user_root / "data" / "ip_investigator.db")
    os.environ["IP_INVESTIGATOR_USER_ROOT"] = str(user_root)
    os.environ["IP_INVESTIGATOR_BUNDLE_ROOT"] = str(bundle)
    os.environ["TMP"] = str(user_root / "tmp")
    os.environ["TEMP"] = str(user_root / "tmp")

    # A watcher is useful in development but unnecessary and fragile in a frozen executable.
    os.environ["STREAMLIT_SERVER_FILE_WATCHER_TYPE"] = "none"
    os.environ["STREAMLIT_BROWSER_GATHER_USAGE_STATS"] = "false"
    os.environ["STREAMLIT_GLOBAL_DEVELOPMENT_MODE"] = "false"

    # Keep .env semantics intuitive: a .env beside the EXE overrides optional API keys.
    exe_dir = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else bundle
    os.chdir(exe_dir)


def _validate_bundle(bundle: Path) -> Path:
    app_script = bundle / "app.py"
    required = (
        app_script,
        bundle / "core",
        bundle / "assets" / "vendor" / "cytoscape.min.js",
        bundle / ".streamlit" / "config.toml",
    )
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise RuntimeError("Build incompleto. Arquivos ausentes: " + ", ".join(missing))
    return app_script


def main() -> int:
    log_path: Path | None = None
    try:
        user_root = _user_root()
        log_path = _setup_logging(user_root)
        logging.info("Inicializando %s", APP_NAME)
        logging.info("Executável: %s", sys.executable)
        logging.info("Frozen: %s", bool(getattr(sys, "frozen", False)))

        bundle = _bundle_root()
        app_script = _validate_bundle(bundle)
        _configure_environment(bundle, user_root)

        port = _available_port()
        url = f"http://127.0.0.1:{port}"
        logging.info("Bundle: %s", bundle)
        logging.info("Dados do usuário: %s", user_root)
        logging.info("Porta selecionada: %s", port)

        threading.Thread(target=_wait_and_open, args=(url,), daemon=True).start()

        # Import after paths and environment are configured. This is intentionally a
        # normal import so PyInstaller can discover Streamlit during Analysis.
        from streamlit.web import cli as stcli

        sys.argv = [
            "streamlit",
            "run",
            str(app_script),
            "--server.address=127.0.0.1",
            f"--server.port={port}",
            "--server.headless=true",
            "--server.fileWatcherType=none",
            "--browser.gatherUsageStats=false",
            "--global.developmentMode=false",
            "--client.toolbarMode=minimal",
        ]
        exit_code = stcli.main()
        return int(exit_code or 0)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 0
        logging.info("Streamlit encerrou com código %s", code)
        if code:
            _show_error(f"O servidor local encerrou com código {code}.", log_path)
        return code
    except Exception as exc:
        if log_path:
            logging.exception("Falha fatal no inicializador")
        _show_error(
            "Não foi possível iniciar o IP Investigator.\n\n"
            f"{exc}\n\n"
            "O aplicativo gravou um log detalhado para diagnóstico.",
            log_path,
        )
        return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        sys.stderr.write(traceback.format_exc())
        raise
