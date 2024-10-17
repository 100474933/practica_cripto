import json
import os

class DataBase:
    def __init__(self):
        self.data = []  # Inicializamos la base de datos como una lista vacía por defecto.

        # Verificamos si el archivo existe
        if os.path.exists('BBDD_users.json'):
            try:
                with open('BBDD_users.json', 'r') as data:
                    content = data.read().strip()  # Leemos el archivo y eliminamos espacios en blanco
                    if content:  # Solo intentamos cargar el JSON si hay contenido
                        self.data = json.loads(content)
            except json.JSONDecodeError:
                print("El archivo de datos está corrupto. Iniciando una base de datos vacía.")
            except Exception as e:
                print(f"Error al leer el archivo: {e}")
    
    def create_account_name(self):
        try:
            name = input("\nINTRODUCE TU NOMBRE: ")
            # Verificamos si el nombre de usuario es único
            for user in self.data:
                if user['name'] == name:
                    raise ValueError(f"EL NOMBRE DE USUARIO {name} YA EXISTE, PORFAVOR INTRODUZCA OTRO")
                
            print("NOMBRE DE USUARIO VÁLIDO.")
                
            return name
            
        except Exception as e:
            raise e

    def create_account_password(self, name):
        #Ahora hacemos lo mismo para la contraseña
        try:    
            password = input("\nINTRODUCE TU CONTRASEÑA: ")
            # Verificamos longitud de la contraseña 
            if len(password) < 8:
                raise ValueError("LA CONTRASEÑA DEBE CONTENER AL MENOS 8 CARACTERES.")
                
            # Verificamos contenido de la contraseña
            mayus = any(char.isupper() for char in password)
            minus = any(char.islower() for char in password)
            num = any(char.isdigit() for char in password)
            if not (mayus and minus and num):
                raise ValueError("LA CONTRASEÑA DEBE CONTENER AL MENOS UNA MAYÚSCULA, UNA MINÚSCULA Y UN NÚMERO.")
                
            print('CONTRASEÑA VÁLIDA.')
                
            # Añadimos el nuevo usuario a la base de datos
            new_user = {'name': name, 'password': password, 'login': False}
            self.data.append(new_user)
            with open('BBDD_users.json', 'w') as bd:
                json.dump(self.data, bd, indent='\t')
                      
        except Exception as e:
            raise e
    
    def login(self, name, password):
        #Comprobamos que el nombre y la contraseña son correctos para ese usuario, si no lanzamos un error. 
        for user in self.data:
            if (user['name'] == name) and (user['password'] == password) and (user['login'] == False):
                user['login'] = True 
                with open('BBDD_users.json', 'w') as bd:
                    json.dump(self.data, bd, indent = '\t')
                return True

        raise ValueError("EL NOMBRE Y/O CONTRAEÑA NO SON CORRECTOS.")

    def logout(self, name):
        #Comprobamos que el usuario esta loggeado para salir de la app.
        for user in self.data:
            if (user['login'] == True) and (user['name'] == name):
                user['login'] = False 
                with open('BBDD_users.json', 'w') as bd:
                    json.dump(self.data, bd, indent = '\t')
                print(f"EL USUARIO {name} CERRO SESIÓN EXITOSAMENTE.")
                return True
        
        raise ValueError("NO SE PUDO CERRAR SESIÓN CORRECTAMENTE")
    


