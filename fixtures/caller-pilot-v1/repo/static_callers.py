from static_helpers import authorize_static_a, can_delete_static_d, owner_static_c, tenant_static_b


def read_a(user, resource):
    return authorize_static_a(user, resource)


def read_b(user, resource):
    return tenant_static_b(user, resource)


def read_c(user, resource):
    return owner_static_c(user, resource)


def read_d(user, resource):
    return can_delete_static_d(user, resource)
