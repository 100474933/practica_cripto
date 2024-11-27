import json
import os
import base64
from encryptation import Encryption

class Users:
    @staticmethod
    def create_BBDD():
        bbdd_path = os.path.abspath('SERVER')
        bbdd_path += '/BBDD'
        os.makedirs(bbdd_path, exist_ok=True)
    
    @staticmethod
    def load_data():
        db_file_path = os.path.abspath('SERVER')
        db_file_path += '/BBDD/BBDD_users.json'
        if os.path.exists(db_file_path):
            try:
                # Obtenemos las rutas de los ficheros que guardan la clave privada y la encriptación de la clave simetrica
                private_key_path = os.path.abspath('SERVER')
                simetric_key_path = private_key_path
                private_key_path += '/keys_and_certificate/private_key.pem' 
                simetric_key_path += '/keys_and_certificate/renting_simetric_encrypted_key.bin'
                # Desencriptamos la base de datos
                Encryption.descifrar_users_json(db_file_path, private_key_path, simetric_key_path)
                
                # Una vez desencriptado la base de datos entramos y leemos los datos
                with open(db_file_path, 'r') as data:
                    content = data.read().strip()  # Leemos el archivo y eliminamos espacios en blanco
                    if content:  # Solo intentamos cargar el JSON si hay contenido
                        return json.loads(content)
            except json.JSONDecodeError:
                print("El archivo de datos está corrupto. Iniciando una base de datos vacía.")
                exit(1)
            except Exception as e:
                print(f"Error al leer el archivo: {e}")
                exit(1)
        return []

    @staticmethod
    def save_data(data):
        db_file_path = os.path.abspath('SERVER/BBDD/BBDD_users.json')
        os.makedirs(os.path.abspath('SERVER/BBDD'), exist_ok=True)

        try:
            # Abrimos el fichero de datos y los guardamos
            with open(db_file_path, 'w') as bbdd_file:
                data = json.dump(data, bbdd_file, indent='\t')
            
            # Ahora procedemos a encriptar el fichero, para ello necesitaremos la clave publica del SERVER
            public_key_path = os.path.abspath('SERVER')
            public_key_path += '/keys_and_certificate/public_key.pem'
            
            # Encriptamos el fichero
            Encryption.cifrar_users_json(db_file_path, public_key_path)
        
        except Exception as e:
            print(f'Error al guardar los datos')
            exit(1)
            
    @staticmethod
    def create_account():
        try:
            # Cargamos los datos de la base de datos (si no existe genera una lista vacía)
            data = Users.load_data()
            
            # Pedimos el nombre de usuario y confirmamos que sea único
            while True:
                name = input("\nINTRODUCE TU NOMBRE: ")
                if any(user['name'] == name for user in data):
                    print(f"El nombre de usuario '{name}' ya existe. Por favor, introduce otro.")
                else:
                    print("NOMBRE DE USUARIO VÁLIDO.")
                    break  # Salimos del bucle si el nombre es válido
            
            # Pedimos la contraseña y confirmamos que cumpla con los estándares mínimos
            while True:
                password = input("\nINTRODUCE TU CONTRASEÑA: ")
                if len(password) < 8:
                    print("La contraseña debe contener al menos 8 caracteres.")
                elif not any(char.isupper() for char in password):
                    print("La contraseña debe contener al menos una mayúscula.")
                elif not any(char.islower() for char in password):
                    print("La contraseña debe contener al menos una minúscula.")
                elif not any(char.isdigit() for char in password):
                    print("La contraseña debe contener al menos un número.")
                else:
                    print("Contraseña válida.")
                    break  # Salimos del bucle si la contraseña es válida
            
            # Generamos una salt
            salt = os.urandom(16)  # Genera una sal aleatoria de 16 bytes

            # Generamos un token con la contraseña y el salt
            token = Encryption.generar_token(password, salt)
            
            # Creamos el nuevo usuario con solo 'salt' y 'token'
            new_user = {
                'name': name,
                'salt': base64.urlsafe_b64encode(salt).decode(),  # Guardamos la sal codificada en base64
                'token': token.decode(),  # Guardamos el token (contraseña cifrada) como string
                'login': False
            }
            
            # Añadimos el nuevo usuario a la base de datos (lista en memoria)
            data.append(new_user)
            Users.save_data(data)
            
            # Creamos las claves del usuario y su certificado digital
            print('\nGenerando cuenta, espere unos segundos.')
            Encryption.user_keys_and_certificate(name)    

        except Exception as e:
            raise e
            
    @staticmethod
    def login(name, password):
        try:
            print(f"[DEBUG] Intentando iniciar sesión con el usuario: {name}")

            # Cargar datos de usuarios
            data = Users.load_data()

            # Buscar usuario en la base de datos
            for user in data:
                if user['name'] == name:
                    print(f"[DEBUG] Usuario encontrado: {name}")

                    # Validar contraseña
                    salt = base64.urlsafe_b64decode(user['salt'])
                    token = user['token'].encode()
                    new_token = Encryption.generar_token(password, salt)

                    if token == new_token:
                        print(f"[DEBUG] Contraseña válida para el usuario: {name}")
                        user['login'] = True

                        # Guardar estado de login
                        Users.save_data(data)

                        # Generar clave de sesión
                        session_key = Encryption.crear_clave_sesion(name)
                        print(f"[DEBUG] Clave de sesión generada: {session_key}")

                        break
                    else:
                        print("[ERROR] Contraseña incorrecta.")
                        return

            else:
                print("[ERROR] Usuario no encontrado.")
                return Users.login()

        except Exception as e:
            print(f"[ERROR] No se pudo iniciar sesión: {e}")
            return Users.login()


    @staticmethod
    def logout(name):
        try:
            data = Users.load_data()
            for user in data:
                if 'login' in user and 'name' in user and user['login'] == True and user['name'] == name:
                    user['login'] = False 
                    Users.save_data(data)
                    print(f"El usuario {name} cerró sesión exitosamente.")
                    
                    # Eliminar clave de sesión
                    Encryption.eliminar_clave_sesion(name)
                    
        except Exception as e:
            print(f'No se pudo cerrar sesión correctamente: {e}')
