import json
import os
import base64
from encryptation import Encryption

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
    
    def create_account(self, name, password):
        try:
            # Verificamos si el nombre de usuario es único
            for user in self.data:
                if user['name'] == name:
                    raise ValueError(f"El nombre de usuario {name} ya existe, por favor introduce otro.")
            
            print("Nombre de usuario válido.")
            
            # Verificamos longitud de la contraseña 
            if len(password) < 8:
                raise ValueError("La contraseña debe contener al menos 8 caracteres.")
            
            # Verificamos contenido de la contraseña
            mayus = any(char.isupper() for char in password)
            minus = any(char.islower() for char in password)
            num = any(char.isdigit() for char in password)
            if not (mayus and minus and num):
                raise ValueError("La contraseña debe contener al menos una mayúscula, una minúscula y un número.")
            
            # Generamos una sal y un token para la contraseña
            salt = os.urandom(16)
            key = Encryption.cifrar_key(password, salt)
            token = Encryption.cifrar_datos(password, key)
            
            # Añadimos el nuevo usuario a la base de datos
            new_user = {
                'name': name,
                'salt': base64.urlsafe_b64encode(salt).decode(),
                'token': token.decode(),
                'login': False
            }
            self.data.append(new_user)
            with open('BBDD_users.json', 'w') as bd:
                json.dump(self.data, bd, indent='\t')
                      
        except Exception as e:
            raise e
    
    def login(self, name, password):
        try:
            for user in self.data:
                if user['name'] == name:
                    salt = base64.urlsafe_b64decode(user['salt'])
                    token = user['token'].encode()
                    
                    # Generamos la clave a partir de la contraseña ingresada y la sal almacenada
                    key = Encryption.cifrar_key(password, salt)
                    
                    # Verificamos y desciframos el token
                    decrypted_password = Encryption.descifrar_datos(token, key)
                    
                    if decrypted_password == password and user['login'] == False:
                        user['login'] = True 
                        with open('BBDD_users.json', 'w') as bd:
                            json.dump(self.data, bd, indent='\t')
                        return True

            raise ValueError("El nombre y/o contraseña no son correctos.")
        except Exception as e:
            raise e

    def logout(self, name):
        try:
            for user in self.data:
                if user['login'] == True and user['name'] == name:
                    user['login'] = False 
                    with open('BBDD_users.json', 'w') as bd:
                        json.dump(self.data, bd, indent='\t')
                    print(f"El usuario {name} cerró sesión exitosamente.")
                    return True
        
            raise ValueError("No se pudo cerrar sesión correctamente")
        except Exception as e:
            raise e