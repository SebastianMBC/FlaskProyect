import mysql.connector

def get_connection():
    conexion = mysql.connector.connect(
        # El host siempre es este para tu cuenta:
        host="mysql-sebastianmateo.alwaysdata.net", 
        
        # OJO: AlwaysData suele usar tu nombre de cuenta como prefijo.
        # Basado en tu URL de administración, tu usuario real es:
        user="sebastianmateo", 
        
        # La contraseña que elegiste al crear el usuario en AlwaysData
        password="Baldeon_2000", 
        
        # El nombre de la base de datos (tal cual sale en tu captura)
        database="sebastianmateo_616",
        
        port=3306 
    )
    return conexion