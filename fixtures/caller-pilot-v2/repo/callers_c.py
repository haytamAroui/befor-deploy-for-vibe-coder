import subprocess
from pathlib import Path

import httpx
from markupsafe import escape

from helpers_c import canonical_upload_name, command_value, html_value, request_target

UPLOAD_ROOT = Path("/srv/uploads")
ALLOWED_URLS = {"https://api.internal.example/status"}


def store_document(name, data):
    candidate = (UPLOAD_ROOT / canonical_upload_name(name)).resolve()
    if candidate.is_relative_to(UPLOAD_ROOT.resolve()):
        candidate.write_bytes(data)


def fetch_status(request):
    return httpx.get(request_target(request)) if request_target(request) in ALLOWED_URLS else None


def render_profile(user_input):
    return render_safe(escape(html_value(user_input)))


def run_choice(choice):
    return subprocess.run(["tool", command_value(choice)], shell=False, check=True)


def render_safe(value):
    return f"<p>{value}</p>"
