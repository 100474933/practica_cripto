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
            
            # Generamos una sal y una clave
            salt = os.urandom(16)
            key = Encryption.cifrar_key(password, salt)
            
            # Ciframos la contraseña
            encrypted_password = Encryption.cifrar_datos(password, key)
            print(f"Cifrado simétrico con Fernet y clave de longitud {len(key)*8} bits.")
            
            # Generamos HMAC para la contraseña cifrada
            mac = Encryption.generar_hmac(encrypted_password.decode(), key)
            print(f"HMAC generado con algoritmo SHA-256 y clave de longitud {len(key)*8} bits.")

            # Añadimos el nuevo usuario a la base de datos
            new_user = {
                'name': name,
                'salt': base64.urlsafe_b64encode(salt).decode(),
                'password': encrypted_password.decode(),
                'mac': mac.decode(),
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
                    encrypted_password = user['password'].encode()
                    mac = user['mac'].encode()
                    
                    # Generamos la clave a partir de la contraseña ingresada y la sal almacenada
                    key = Encryption.cifrar_key(password, salt)
                    
                    # Verificamos HMAC
                    if not Encryption.verificar_hmac(encrypted_password.decode(), key, mac):
                        raise ValueError("La integridad de la contraseña almacenada no se puede verificar.")
                    print(f"Verificación HMAC con algoritmo SHA-256 y clave de longitud {len(key)*8} bits.")
                    
                    # Desciframos la contraseña almacenada
                    decrypted_password = Encryption.descifrar_datos(encrypted_password, key)
                    print(f"Descifrado simétrico con Fernet y clave de longitud {len(key)*8} bits.")
                    
                    if decrypted_password == password and user['login'] == False:
                        user['login'] = True 
                        with open('BBDD_users.json', 'w') as bd:
                            json.dump(self.data, bd, indent='\t')
                        return True

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
    

