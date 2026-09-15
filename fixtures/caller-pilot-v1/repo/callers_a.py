from helpers_a import authorize_action, may_delete, owner_matches, tenant_matches


def read_one(user, resource):
    return authorize_action(user, resource)


def read_two(user, resource):
    return tenant_matches(user, resource)


def read_three(user, resource):
    return owner_matches(user, resource)


def read_four(user, resource):
    return may_delete(user, resource)
