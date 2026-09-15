import subprocess
from pathlib import Path

import httpx
from markupsafe import escape

from trap_helpers import normalize_upload_name_trap_a, raw_html_trap_c, shell_arg_trap_d, target_url_trap_b

UPLOAD_ROOT = Path("/srv/uploads")
ALLOWED_URLS = {"https://api.internal.example/status"}


def upload_trap_a(name, data):
    candidate = (UPLOAD_ROOT / normalize_upload_name_trap_a(name)).resolve()
    if candidate.is_relative_to(UPLOAD_ROOT.resolve()):
        candidate.write_bytes(data)


def fetch_trap_b(request):
    return httpx.get(target_url_trap_b(request)) if target_url_trap_b(request) in ALLOWED_URLS else None


def render_trap_c(user_input):
    return render_safe(escape(raw_html_trap_c(user_input)))


def command_trap_d(choice):
    return subprocess.run(["tool", shell_arg_trap_d(choice)], shell=False, check=True)


def render_safe(value):
    return f"<p>{value}</p>"
