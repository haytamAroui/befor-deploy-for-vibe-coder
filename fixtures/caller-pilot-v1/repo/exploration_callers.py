from pathlib import Path

import httpx

from exploration_helpers import access_mode_exp_a, billing_units_exp_d, normalize_upload_name_exp_b, target_url_exp_c

UPLOAD_ROOT = Path("/srv/uploads")


def delete_exp_a(user, resource):
    if access_mode_exp_a(user) != "blocked":
        resource.delete()


def upload_exp_b(name, data):
    (UPLOAD_ROOT / normalize_upload_name_exp_b(name)).write_bytes(data)


def fetch_exp_c(request):
    return httpx.get(target_url_exp_c(request))


def charge_exp_d(invoice, ledger):
    ledger.charge(billing_units_exp_d(invoice.total))
