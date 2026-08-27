def lookup_account(cursor, account_id):
    query = "SELECT * FROM accounts WHERE id = ?"
    aliased_query = query
    cursor.execute(aliased_query, (account_id,))
