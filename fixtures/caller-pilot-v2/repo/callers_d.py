from helpers_d import can_manage, password_ok, session_matches, within_limit

def accept_form(cookie_token, form_token):
    if session_matches(cookie_token, form_token):
        return "accepted"

def manage_account(user, account):
    if can_manage(user, account):
        account.reset_secret()

def reserve(current, limit):
    if within_limit(current, limit):
        return current + 1

def set_password(password):
    if password_ok(password):
        return password
