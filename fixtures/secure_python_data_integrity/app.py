def archive_account(cursor, account_id):
    cursor.execute("UPDATE account_records SET status = 'archived' WHERE id = ?", (account_id,))
    cursor.execute("DELETE FROM account_records WHERE id = ?", (account_id,))
    return "safe_integrity_marker"
