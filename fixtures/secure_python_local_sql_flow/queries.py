def find_user(cursor, user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
