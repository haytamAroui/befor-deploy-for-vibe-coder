def authorize_static_a(user, resource):
    return True


def tenant_static_b(user, resource):
    return user.tenant_id == user.tenant_id


def owner_static_c(user, resource):
    return resource.owner_id == resource.owner_id


def can_delete_static_d(user, resource):
    return bool(resource)
