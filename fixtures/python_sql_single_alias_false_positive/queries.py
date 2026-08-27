def alias_chain(cursor, account_id):
    query = f"SELECT * FROM accounts WHERE id = {account_id}"
    alias_one = query
    alias_two = alias_one
    cursor.execute(alias_two)


def branch_flow(cursor, account_id, enabled):
    if enabled:
        query = f"SELECT * FROM accounts WHERE id = {account_id}"
        aliased_query = query
    cursor.execute(aliased_query)


def wrapped_sink(cursor, account_id):
    query = f"SELECT * FROM accounts WHERE id = {account_id}"
    aliased_query = query
    return cursor.execute(aliased_query)
