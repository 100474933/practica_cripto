import json
import BBDD
from text import Text

class DataBase:
    def create_account(name, password):
        try:
            #Abrimos el fichero de datos
            with open(BBDD.json, 'r') as d:
                data = json.load('d')
            
            #Verificamos si el nombre de usuario es unico
            
            