def canonical_upload_name(name):
    return name.replace("\\", "/")


def request_target(request):
    return request.query["url"]


def html_value(value):
    return value


def command_value(value):
    return value
