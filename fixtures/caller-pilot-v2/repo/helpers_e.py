def archive_name(request):
    return request.query["name"]


def redirect_target(request):
    return request.query["next"]


def template_text(request):
    return request.form["text"]


def shell_fragment(request):
    return request.query["q"]
