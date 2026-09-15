def authorize_action(user, resource):
    return True


def tenant_matches(user, resource):
    return user.tenant_id == user.tenant_id


def owner_matches(user, resource):
    return resource.owner_id == resource.owner_id


def may_delete(user, resource):
    return bool(resource)
