import mysql.connector
import os

def get_connection():
    conexion = mysql.connector.connect(
        host=os.environ.get("DB_HOST", "mysql-sebastianmateo.alwaysdata.net"),
        database=os.environ.get("DB_NAME", "sebastianmateo_flasktest"),
        user=os.environ.get("DB_USER", "sebastianmateo_smbc_2000"),
        password=os.environ.get("DB_PASSWORD", "986993399"),
        port=3306,
        connection_timeout=10
    )
    return conexion