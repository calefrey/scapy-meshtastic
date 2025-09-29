import sqlite3


class Databse(sqlite3.Connection):
    def __init__(self, filename: str = "database.db"):
        super().__init__(database=filename)  # do the default initialization
        cur = self.cursor()
        data_cols = [
            "src",
            "dst",
            "packet_id",
            "payload",
            "appname",
            "appdata",
        ]

        nodeinfo_cols = [
            "macaddr",
            "publicKey",
            "shortName",
            "longName",
            "role",
            "isUnmessagable",
            "hwModel",
            "last_updated",
        ]

        cur.execute(f"""
            CREATE TABLE if not exists data (
                _timestamp PRIMARY KEY,
                {",".join(data_cols)}
            )
        """)

        cur.execute(f"""
            CREATE TABLE if not exists nodes (
                _id PRIMARY KEY,
                {",".join(nodeinfo_cols)})
        """)
        self.commit()
        return

    def insert(
        self: sqlite3.Connection,
        table: str,
        data: dict,
        on_confict: str | None = None,
    ):
        """
        Add a row to a table, using dict keys as column names.

        on_conflict specifies the conflict resolution action, either "REPLACE" or "IGNORE"
        """
        cur = self.cursor()

        assert on_confict in [None, "REPLACE", "IGNORE"]
        # get existing db columns
        cur.execute(f"PRAGMA table_info({table})")
        db_cols = [col[1] for col in cur.fetchall()]

        # remove anything that doesn't match
        data = {k: v for k, v in data.items() if k in db_cols}

        # generate strings for sql statement columns
        columns = ",".join(data.keys())
        named_params = ":" + ", :".join(data.keys())
        verb = "INSERT"
        if on_confict:
            verb += " OR " + on_confict
        sql = f"{verb} INTO {table}({columns}) VALUES({named_params})"
        try:
            cur.execute(sql, data)
            self.commit()
        except sqlite3.Error as e:
            print(sql)
            print(data)
            raise e
