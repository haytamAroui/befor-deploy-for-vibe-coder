def dynamic_mutation(cursor, table_name):
    query = f"DELETE FROM {table_name}"
    cursor.execute(query)


def variable_mutation(cursor, query):
    cursor.execute(query)


class Repository:
    def delete_all(self):
        self.objects.delete()
