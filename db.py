import mysql.connector

def get_connection():
    conexion = mysql.connector.connect(
        host="mysql-sebastianmateo.alwaysdata.net", 
        user="sebastianmateo", 
        password="Baldeon_2000", 
        database="sebastianmateo_616",
        port=3306 
    )
    return conexion