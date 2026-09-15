import subprocess
from pathlib import Path
from markupsafe import Markup
from starlette.responses import RedirectResponse
from helpers_e import archive_name, redirect_target, shell_fragment, template_text

ARCHIVE_ROOT = Path("/srv/archive")

def read_archive(request):
    return (ARCHIVE_ROOT / archive_name(request)).read_bytes()

def redirect_after_login(request):
    return RedirectResponse(redirect_target(request))

def render_note(request):
    return Markup(template_text(request))

def grep_records(request):
    subprocess.run(f"grep {shell_fragment(request)} records.txt", shell=True, check=True)
