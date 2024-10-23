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
                    raise ValueError(f"El nombre de usuario {name} ya existe.")
            
            # Verificamos que la contraseña cumpla con las reglas
            if len(password) < 8:
                raise ValueError("La contraseña debe contener al menos 8 caracteres.")
            
            # Generamos la sal y derivamos la clave simétrica a partir de la contraseña
            salt = os.urandom(16)  # Genera una sal aleatoria de 16 bytes
            key = Encryption.cifrar_key(password, salt)  # Deriva la clave simétrica usando la contraseña y la sal
            
            # Ciframos la contraseña con la clave derivada
            token = Encryption.cifrar_datos(password, key)  # Cifra la contraseña
            
            # Creamos el nuevo usuario con solo 'salt' y 'token'
            new_user = {
                'salt': base64.urlsafe_b64encode(salt).decode(),  # Guardamos la sal codificada en base64
                'token': token.decode()  # Guardamos el token (contraseña cifrada) como string
            }
            
            # Añadimos el nuevo usuario a la base de datos (lista en memoria)
            self.data.append(new_user)
            
            # Escribimos los cambios en el archivo JSON
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
                    encrypted_key = base64.urlsafe_b64decode(user['encrypted_key'])

                    key = Encryption.descifrar_key_rsa(encrypted_key, self.private_key)  # Descifrar clave con RSA
                    decrypted_password = Encryption.descifrar_datos(token, key)

                    if decrypted_password == password and not user['login']:
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