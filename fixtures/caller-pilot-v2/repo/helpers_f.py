def record_key(request):
    return request.query["id"]


def header_text(request):
    return request.query["name"]


def result_limit(request):
    return request.query["limit"]


def outbound_host(request):
    return request.query["host"]
