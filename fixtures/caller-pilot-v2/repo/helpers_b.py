def access_mode(user):
    return user.mode


def normalize_upload_name(name):
    return name.replace("\\", "/")


def target_url(request):
    return request.query["url"]


def billing_units(amount):
    return int(amount)
