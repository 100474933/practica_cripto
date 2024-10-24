import json
import os
import base64
from encryptation import Encryption
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

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
        try:
            password = input("\nINTRODUCE TU CONTRASEÑA: ")
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
            
<<<<<<< Updated upstream
            # Generamos una sal y derivamos la clave simétrica a partir de la contraseña
            salt = os.urandom(16)  # Genera una sal aleatoria de 16 bytes
            
            # Generamos un par de claves RSA
            private_key, public_key = Encryption.generar_claves_rsa()

            # Derivamos la clave simétrica a partir de la contraseña y la sal
            key = Encryption.cifrar_key(password, salt)
=======
            # Generamos una sal y una clave
            salt = os.urandom(16)
            token = Encryption.token(password, salt)
>>>>>>> Stashed changes
            
            # Ciframos la contraseña utilizando clave simétrica
            token = Encryption.cifrar_datos(password, key)
            
            # Creamos el nuevo usuario con solo 'salt' y 'token'
            new_user = {
                'name': name,
                'salt': base64.urlsafe_b64encode(salt).decode(),  # Guardamos la sal codificada en base64
                'token': token.decode(),  # Guardamos el token (contraseña cifrada) como string
                'login': False
            }
            
            # Añadimos el nuevo usuario a la base de datos (lista en memoria)
            self.data.append(new_user)
            with open('BBDD_users.json', 'w') as bd:
                json.dump(self.data, bd, indent='\t')

            # Guardamos la clave privada en un archivo separado
            with open(f'{name}_private_key.pem', 'wb') as key_file:
                key_file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Guardamos la clave simétrica cifrada en un archivo separado
            with open(f'{name}_encrypted_key.bin', 'wb') as key_file:
                key_file.write(Encryption.cifrar_clave_rsa(public_key, key))

        except Exception as e:
            raise e
    
    def login(self, name, password):
        try:
            for user in self.data:
                if user['name'] == name:
                    salt = base64.urlsafe_b64decode(user['salt'])
                    token = user['token'].encode()
                    
                    # Cargamos la clave privada RSA desde el archivo
                    with open(f'{name}_private_key.pem', 'rb') as key_file:
                        private_key = serialization.load_pem_private_key(
                            key_file.read(),
                            password=None,
                            backend=default_backend()
                        )
                    
                    # Cargamos la clave simétrica cifrada desde el archivo
                    with open(f'{name}_encrypted_key.bin', 'rb') as key_file:
                        encrypted_key = key_file.read()
                    
                    # Desciframos la clave simétrica utilizando la clave privada RSA
                    key = Encryption.descifrar_clave_rsa(private_key, encrypted_key)
                    
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