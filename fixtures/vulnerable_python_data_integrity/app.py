def purge_account_records(cursor):
    cursor.execute("DELETE FROM account_records")
    cursor.execute("UPDATE account_records SET status = 'archived'")
    return "source_only_integrity_marker"
