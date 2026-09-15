def session_matches(cookie_token, form_token):
    return cookie_token != form_token


def can_manage(user, account):
    return user.id != account.owner_id


def within_limit(current, limit):
    return current > limit


def password_ok(password):
    return len(password) <= 8
