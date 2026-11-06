"""Universal Camofox human-auth plugin.

The plugin contains the runtime tools; the bundled skill contains the
provider-agnostic handoff procedure. Secrets are entered by the user in the
browser and are never passed as tool arguments.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen


def _env(name: str, default: str = "") -> str:
    """Read a plugin config env var honouring the per-profile secret scope.

    Plain os.getenv() hands back whatever the PROCESS environment holds —
    under a multiplexed gateway (several profiles sharing one Hermes
    process) that is some arbitrary profile's value, not necessarily this
    one's, because dotenv values get merged into the single process env at
    load time per-profile-turn, not per-profile-forever. get_secret()
    already resolves this correctly for every case (global vars, bound
    scope, multiplex on/off) — see agent/secret_scope.py. Falls back to
    raw os.getenv only if the module itself cannot be imported at all
    (shouldn't happen inside a running Hermes, kept defensive for CLI/
    standalone script contexts)."""
    try:
        from agent.secret_scope import get_secret
        value = get_secret(name, default)
        return (value or "").strip() if value is not None else default
    except Exception:
        return os.getenv(name, default).strip()


def _backend() -> str:
    return _env("CAMOFOX_HUMAN_AUTH_BACKEND", "native").lower() or "native"


def _profile_dir() -> str:
    configured = _env("CAMOFOX_PROFILE_DIR", "")
    return configured or str(Path(__file__).parent / "data" / "profiles")


def _session_defaults() -> tuple[str, str]:
    return (
        _env("CAMOFOX_HUMAN_AUTH_USER_ID", "hermes") or "hermes",
        _env("CAMOFOX_HUMAN_AUTH_SESSION_KEY", "native-auth") or "native-auth",
    )


def _base_url() -> str:
    # CAMOFOX_URL is the existing camofox browser-toolset's own REST URL env var;
    # reuse it as a fallback so profiles that already set it (e.g. child Docker
    # installs) don't need a second, duplicate variable for this plugin.
    default = "http://127.0.0.1:9378" if _backend() == "docker" else "http://127.0.0.1:9377"
    fallback = _env("CAMOFOX_URL", default)
    return _env("CAMOFOX_HUMAN_AUTH_URL", fallback).rstrip("/")


def _novnc_url() -> str:
    # CAMOFOX_NOVNC_PASSWORD (optional): when set, appended as
    # ?password=...&autoconnect=true so the handoff link opens straight
    # into the session without the noVNC connect form — same password the
    # camofox-browser container's own VNC_PASSWORD env var was given, not a
    # separate secret. Works for BOTH the explicit CAMOFOX_NOVNC_PUBLIC_URL
    # override and the auto-derived host:port fallback below.
    explicit = _env("CAMOFOX_NOVNC_PUBLIC_URL", "")
    password = _env("CAMOFOX_NOVNC_PASSWORD", "")
    query = f"?password={password}&autoconnect=true" if password else ""
    if explicit:
        return explicit.rstrip("/") + "/vnc.html" + query
    parsed = urlsplit(_base_url())
    host = parsed.hostname or "127.0.0.1"
    port = _env("CAMOFOX_NOVNC_PORT", "6089")
    return urlunsplit((parsed.scheme or "http", f"{host}:{port}", "/vnc.html", query.lstrip("?"), ""))


def _request(path: str, payload: dict | None = None, timeout: float = 60) -> dict:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    admin_key = _env("CAMOFOX_HUMAN_AUTH_ADMIN_KEY", "")
    if admin_key:
        headers["x-admin-key"] = admin_key
    request = Request(_base_url() + path, data=body, headers=headers, method="POST" if body else "GET")
    with urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def _ensure_native_backend() -> None:
    """Start the installed patched native backend when the port is down."""
    if _backend() != "native":
        return
    try:
        health = _request("/health", timeout=3)
        if health.get("ok") and health.get("browserConnected"):
            return
    except Exception:
        pass

    root = Path(__file__).parent
    script = root / "scripts" / "start-native.ps1"
    if os.name != "nt" or not script.exists():
        raise RuntimeError(f"Native Camofox backend is unavailable and startup script is missing: {script}")

    log_dir = root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = open(log_dir / "native-autostart.log", "a", encoding="utf-8")
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-DisplayMode", "headless"],
        cwd=str(root),
        stdout=log_file,
        stderr=subprocess.STDOUT,
        creationflags=flags,
        close_fds=True,
    )
    for _ in range(60):
        try:
            health = _request("/health", timeout=2)
            if health.get("ok") and health.get("browserConnected"):
                return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("Native Camofox backend did not become ready within 30 seconds")


def _status(_args=None, **_kwargs):
    default_user_id, default_session_key = _session_defaults()
    result = {
        "backend": _backend(),
        "camofox_url": _base_url(),
        "profile_dir": _profile_dir(),
        "default_user_id": default_user_id,
        "default_session_key": default_session_key,
        "api_ok": False,
        "ready": False,
    }
    if _backend() == "docker":
        result["novnc_url"] = _novnc_url()
    try:
        health = _request("/health")
        result["health"] = health
        result["api_ok"] = bool(health.get("ok"))
        result["ready"] = result["api_ok"] and bool(health.get("browserConnected"))
    except Exception as exc:
        result["error"] = f"Camofox is unavailable: {exc}"
    return json.dumps(result, ensure_ascii=False)


def _auth_open(args=None, **_kwargs):
    args = args or {}
    url = str(args.get("url", "")).strip()
    default_user_id, default_session_key = _session_defaults()
    user_id = str(args.get("user_id", default_user_id)).strip()
    session_key = str(args.get("session_key", default_session_key)).strip()
    if not url or not user_id or not session_key:
        return json.dumps({"ok": False, "error": "url, user_id and session_key are required"})
    headed_requested = False
    try:
        if _backend() == "docker":
            result = _request("/tabs", {"userId": user_id, "sessionKey": session_key, "url": url})
            return json.dumps({"ok": True, "backend": "docker", "user_id": user_id, "session_key": session_key, "profile_dir": _profile_dir(), "tab": result, "user_action_url": _novnc_url()}, ensure_ascii=False)
        _ensure_native_backend()
        mode = _request("/admin/display-mode", {"mode": "headed"}, timeout=60)
        headed_requested = True
        tab = _request("/tabs", {"userId": user_id, "sessionKey": session_key, "url": url}, timeout=90)
        return json.dumps({"ok": True, "backend": "native", "user_id": user_id, "session_key": session_key, "profile_dir": _profile_dir(), "mode": mode, "tab": tab, "window_opened": True}, ensure_ascii=False)
    except Exception as exc:
        if headed_requested:
            try:
                _request("/admin/display-mode", {"mode": "headless"}, timeout=60)
            except Exception:
                pass
        return json.dumps({"ok": False, "error": str(exc), "backend": _backend()}, ensure_ascii=False)


def _auth_finish(args=None, **_kwargs):
    args = args or {}
    default_user_id, default_session_key = _session_defaults()
    user_id = str(args.get("user_id", default_user_id)).strip()
    session_key = str(args.get("session_key", default_session_key)).strip()
    url = str(args.get("url", "")).strip()
    try:
        if _backend() == "docker":
            return json.dumps({"ok": True, "backend": "docker", "user_id": user_id, "session_key": session_key, "profile_dir": _profile_dir(), "message": "Keep using the existing noVNC session and verify the page."}, ensure_ascii=False)
        _ensure_native_backend()
        mode = _request("/admin/display-mode", {"mode": "headless"}, timeout=60)
        tab = None
        if url:
            tab = _request("/tabs", {"userId": user_id, "sessionKey": session_key, "url": url}, timeout=90)
        return json.dumps({"ok": True, "backend": "native", "user_id": user_id, "session_key": session_key, "profile_dir": _profile_dir(), "mode": mode, "tab": tab, "headless_resumed": True}, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"ok": False, "error": str(exc), "backend": _backend()}, ensure_ascii=False)


def _cli_setup_argparse(subparser):
    subs = subparser.add_subparsers(dest="camofox_human_auth_command")
    subs.add_parser("setup", help="Detect OS and choose Local native or VPS/Server Docker backend")
    subs.add_parser("status", help="Show configured Camofox backend status")
    subparser.set_defaults(func=_cli_handler)


def _cli_handler(args):
    command = getattr(args, "camofox_human_auth_command", None)
    if command == "status":
        print(_status())
        return
    if command != "setup":
        print("Usage: hermes camofox-human-auth <setup|status>")
        return
    root = Path(__file__).parent
    if os.name == "nt":
        script = root / "scripts" / "setup.ps1"
        command_line = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)]
    else:
        script = root / "scripts" / "setup.sh"
        command_line = ["bash", str(script)]
    if not script.exists():
        raise RuntimeError(f"Setup script is missing: {script}")
    import subprocess
    raise SystemExit(subprocess.call(command_line, cwd=str(root)))


def register(ctx) -> None:
    skills_dir = Path(__file__).parent / "skills"
    skill_md = skills_dir / "human-auth" / "SKILL.md"
    if skill_md.exists():
        ctx.register_skill("human-auth", skill_md)
    ctx.register_cli_command(
        name="camofox-human-auth",
        help="Install and manage universal Camofox human-auth backend",
        setup_fn=_cli_setup_argparse,
        handler_fn=_cli_handler,
    )

    ctx.register_tool(
        name="camofox_backend_status",
        toolset="camofox",
        schema={"name": "camofox_backend_status", "description": "Check the configured Camofox backend and health.", "parameters": {"type": "object", "properties": {}, "additionalProperties": False}},
        handler=_status,
        check_fn=lambda: True,
        description="Check whether Local native or VPS/Server Docker Camofox is available.",
        emoji="🦊",
    )
    ctx.register_tool(
        name="camofox_auth_open",
        toolset="camofox",
        schema={"name": "camofox_auth_open", "description": "Open the existing user-controlled Camofox auth surface using the configured persistent profile. Use for any login, registration, SSO, MFA, OTP, CAPTCHA, or device-confirmation flow. Reuse the same user_id=hermes and session_key=native-auth; never pass secrets and never create a new profile.", "parameters": {"type": "object", "required": ["url"], "properties": {"url": {"type": "string"}, "user_id": {"type": "string"}, "session_key": {"type": "string"}}, "additionalProperties": False}},
        handler=_auth_open,
        check_fn=lambda: True,
        description="Open native headed Camoufox or return the Docker/noVNC handoff surface.",
        emoji="🔐",
    )
    ctx.register_tool(
        name="camofox_auth_finish",
        toolset="camofox",
        schema={"name": "camofox_auth_finish", "description": "Finish the existing user-controlled authentication handoff using exactly the same persistent profile, user_id, and session_key returned by camofox_auth_open. Do not accept passwords or OTP values and do not open a new tab/profile.", "parameters": {"type": "object", "properties": {"url": {"type": "string"}, "user_id": {"type": "string"}, "session_key": {"type": "string"}}, "additionalProperties": False}},
        handler=_auth_finish,
        check_fn=lambda: True,
        description="Return native Camofox to headless mode after the user completes authentication.",
        emoji="✅",
    )
