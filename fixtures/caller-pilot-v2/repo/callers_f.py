from helpers_f import header_text, outbound_host, record_key, result_limit

ALLOWED_HOSTS = {"api.example.com"}


def load_record(db, request):
    return db.execute("SELECT * FROM records WHERE id = ?", (record_key(request),))

def set_download_header(response, request):
    value = header_text(request)
    if "\r" in value or "\n" in value: raise ValueError("invalid header")
    response.headers["X-Name"] = value

def page_size(request):
    value = int(result_limit(request))
    return max(1, min(value, 100))

def fetch_allowed(client, request):
    host = outbound_host(request)
    if host not in ALLOWED_HOSTS: raise ValueError("host not allowed")
    return client.get(f"https://{host}/status")
