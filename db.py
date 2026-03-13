import mysql.connector

def get_connection():
    conexion = mysql.connector.connect(
        host="localhost",       # O la IP de tu servidor
        user="root",            # Tu usuario de MySQL (suele ser root en local)
        password="",            # Tu contraseña (vacía si usas XAMPP por defecto)
        database="sebastianmateo_616" # El nombre de la base de datos que creaste
    )
    return conexion