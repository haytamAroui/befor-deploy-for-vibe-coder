def normalize_upload_name_trap_a(name):
    return name.replace("\\", "/")


def target_url_trap_b(request):
    return request.query["url"]


def raw_html_trap_c(value):
    return value


def shell_arg_trap_d(value):
    return value
