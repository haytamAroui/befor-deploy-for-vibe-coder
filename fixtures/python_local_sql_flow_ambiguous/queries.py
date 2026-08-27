def find_user(cursor, user_id, include_inactive):
    if include_inactive:
        query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
