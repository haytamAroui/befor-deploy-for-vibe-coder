def access_mode_exp_a(user):
    return user.mode


def normalize_upload_name_exp_b(name):
    return name.replace("\\", "/")


def target_url_exp_c(request):
    return request.query["url"]


def billing_units_exp_d(amount):
    return int(amount)
