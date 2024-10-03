import json
from text import Text

class DataBase:
    def create_account(bbdd, name, password):
        try:
            #Abrimos el fichero de datos
            with open(bbdd, 'r') as d:
                data = json.load('d')
            
            #Verificamos si el nombre de usuario es unico
            for user in data:
                if user['name'] == name:
                    raise ValueError(f"El nombre de usuario '{name}' ya existe, por favor introduce otro.")
            
            
                
            