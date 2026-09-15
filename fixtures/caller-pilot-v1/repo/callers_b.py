from pathlib import Path

import httpx

from helpers_b import access_mode, billing_units, normalize_upload_name, target_url

UPLOAD_ROOT = Path("/srv/uploads")


def delete_resource(user, resource):
    if access_mode(user) != "blocked":
        resource.delete()


def store_upload(name, data):
    (UPLOAD_ROOT / normalize_upload_name(name)).write_bytes(data)


def fetch_remote(request):
    return httpx.get(target_url(request))


def charge_invoice(invoice, ledger):
    ledger.charge(billing_units(invoice.total))
