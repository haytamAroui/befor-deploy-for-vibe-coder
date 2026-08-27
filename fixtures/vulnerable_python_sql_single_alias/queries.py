def lookup_account(cursor, account_id):
    query = f"SELECT * FROM accounts WHERE id = {account_id}"
    aliased_query = query
    cursor.execute(aliased_query)
