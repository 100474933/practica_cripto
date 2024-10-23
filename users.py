import json
import os
from encryptation import Encryption
import base64

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
            
            # Generamos la sal y derivamos la clave simétrica a partir de la contraseña
            salt = os.urandom(16)  # Genera una sal aleatoria de 16 bytes
            key = Encryption.cifrar_key(password, salt)  # Deriva la clave simétrica usando la contraseña y la sal
            
            # Ciframos la contraseña con la clave derivada
            token = Encryption.cifrar_datos(password, key)  # Cifra la contraseña
            
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

            raise ValueError("EL NOMBRE Y/O CONTRASEÑA NO SON CORRECTOS.")
        except Exception as e:
            raise e

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
    


