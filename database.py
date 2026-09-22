import os
import mysql.connector

def get_connection():
    return mysql.connector.connect(
        host=os.getenv("ZTNA_DB_HOST", "127.0.0.1"),
        user=os.getenv("ZTNA_DB_USER", "ztna_user"),
        password=os.getenv("ZTNA_DB_PASSWORD"),
        database=os.getenv("ZTNA_DB_NAME", "ztna_gateway"),
        connection_timeout=5
    )
