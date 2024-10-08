import json
import os
from encryption import Encryption


class DataBase:
    def __init__(self):
        self.data = []  # Inicializamos la base de datos como una lista vacía por defecto.

        # Verificamos si el archivo existe
        if os.path.exists('BBDD.json'):
            try:
                with open('BBDD.json', 'r') as data:
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
            
            # Generamos una sal y una clave
            salt = os.urandom(16)
            key = Encryption.cifrar_key(password, salt)
            
            # Ciframos la contraseña
            encrypted_password = Encryption.cifrar_datos(password, key)
            
            # Añadimos el nuevo usuario a la base de datos
            new_user = {
                'name': name,
                'salt': salt.hex(),
                'password': encrypted_password.hex()
            }

            self.data.append(new_user)
            with open('BBDD.json', 'w') as bd:
                json.dump(self.data, bd, indent='\t')
            
            print('Cuenta creada con éxito.')
            return True
            
        except Exception as e:
            raise e
    
    def login(self, name, password):
        for user in self.data:
            if (user['name'] == name) and (user['password'] == password):
                return True

        raise ValueError("El nombre y/o contraseña no son correctos.")


