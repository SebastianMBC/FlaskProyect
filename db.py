import mysql.connector

def get_connection():
    conexion = mysql.connector.connect(
        host="localhost",
        database="newdb",
        user="root",
        password="",
        port=3306
    )
    return conexion