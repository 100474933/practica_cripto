import base64
import os
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class Encryption:
    @staticmethod
    def generar_claves_rsa():
        # Genera un par de claves RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def cifrar_clave_rsa(public_key, clave_simetrica):
        # Cifra la clave simétrica utilizando la clave pública RSA
        encrypted_key = public_key.encrypt(
            clave_simetrica,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key

    @staticmethod
    def descifrar_clave_rsa(private_key, encrypted_key):
        # Descifra la clave simétrica utilizando la clave privada RSA
        decrypted_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_key

    @staticmethod
    def generar_token(password, salt):
        # Crea un objeto PBKDF2HMAC con el algoritmo SHA-256, longitud de clave de 32 bytes, sal y 100000 iteraciones
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()  # Backend criptográfico por defecto
        )
        # Deriva la clave a partir de la contraseña y la codifica en base64
        token = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return token

    @staticmethod
    def cifrar_chacha20(key, plaintext):
        # Generar un nonce aleatorio de 12 bytes 
        nonce = os.urandom(12)
        
        # Crear instancia de ChaCha20Poly1305 con la clave proporcionada
        chacha = ChaCha20Poly1305(key)
        
        # Cifrar el mensaje (plaintext) usando el nonce
        ciphertext = chacha.encrypt(nonce, plaintext, None)
        
        return nonce, ciphertext

    @staticmethod
    def descifrar_chacha20(key, nonce, ciphertext, associated_data=None):
        # Crear instancia de ChaCha20Poly1305 con la clave proporcionada
        chacha = ChaCha20Poly1305(key)
        
        # Descifrar el mensaje usando el nonce y el texto cifrado
        plaintext = chacha.decrypt(nonce, ciphertext, associated_data)
        
        return plaintext
    
    @staticmethod
    def generar_key_chacha20():
        # Generamos la key y la devolvemos
        key = ChaCha20Poly1305.generate_key()
        return key

    @staticmethod
    def server_public_private_keys():
        # Generamos un par de claves para el server, una pública y otra privada
        private_key, public_key = Encryption.generar_claves_rsa()
        
        # Creo una carpeta para almacenar mis bases de datos
        os.makedirs('SERVER', exist_ok=True)
        
        # Creo una carpeta dentro de mi carpeta SERVER para guardar nuestras keys
        keys_path = os.path.abspath('SERVER')
        keys_path += '/KEYS'
        os.makedirs(keys_path, exist_ok=True)
        
        # Ahora junto la ruta de mi carpeta keys con los archivos que contienen las keys
        private_key_path = os.path.join(keys_path, 'server_private_key.pem')
        public_key_path = os.path.join(keys_path, 'server_public_key.pem')
        
        # Guardamos la clave privada en un archivo separado
        with open(private_key_path, 'wb') as key_file:
                    key_file.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
        
        # Guardamos la clave pública en un archivo separado
        with open(public_key_path, 'wb') as key_file:
                    key_file.write(public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))

    @staticmethod
    def cifrar_users_json(json_path, public_key_path):
        """Esta función lo que hara será cifrar el fichero BBDD_users.json, y cifrar asimetricamente
        la clave simétrica que estamos usando para cifrar nuestra base de datos."""
        try:
            # Leemos el fichero json y convertimos el contenido a un string de bytes
            with open(json_path, 'r') as file:
                json_data = json.dumps(json.load(file)).encode('utf-8')
            
            # Ahora generamos una clave con ChaCha20Poly1305 
            key = Encryption.generar_key_chacha20()
            
            # Ahora encriptamos el contenido del json
            nonce, ciphertext = Encryption.cifrar_chacha20(key, json_data)
            
            # Para almacenar la clave y el nonce de forma segura, codificamos en base64
            nonce_b64 = base64.urlsafe_b64encode(nonce).decode()
            ciphertext_b64 = base64.urlsafe_b64encode(ciphertext).decode()
            
            cipherdata = {
                'nonce': nonce_b64,
                'ciphertext': ciphertext_b64
            }
            
            with open(json_path, 'w') as file:
                json.dump(cipherdata, file, indent='\t')
            
            # Ahora genero un fichero que es donde guardaremos el cifrado de la clave simetrica con la clave publica del server
            keys_path = os.path.abspath('SERVER')
            keys_path += '/KEYS'
            simetric_key_path = os.path.join(keys_path, 'users_simetric_encrypted_key.bin')
            
            # Abrimos el fichero que maneja la clave publica, para cifrar la clave simétrica
            with open(public_key_path, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
                )
            
            # Guardamos la clave simétrica cifrada en un archivo separado
            with open(simetric_key_path, 'wb') as key_file:
                key_file.write(Encryption.cifrar_clave_rsa(public_key, key))
        
        except Exception as e:
            print(f'Error al cifrar el fichero JSON.')
            exit(1)
        
    @staticmethod
    def cifrar_renting_json(json_path, public_key_path):
        """Esta función lo que hara será cifrar el fichero BBDD_renting.json, y cifrar asimetricamente
        la clave simétrica que estamos usando para cifrar nuestra base de datos."""
        try:
            # Leemos el fichero json y convertimos el contenido a un string de bytes
            with open(json_path, 'r') as file:
                json_data = json.dumps(json.load(file)).encode('utf-8')
            
            # Ahora generamos una clave con ChaCha20Poly1305 
            key = Encryption.generar_key_chacha20()
            
            # Ahora encriptamos el contenido del json
            nonce, ciphertext = Encryption.cifrar_chacha20(key, json_data)
            
            # Para almacenar la clave y el nonce de forma segura, codificamos en base64
            nonce_b64 = base64.urlsafe_b64encode(nonce).decode()
            ciphertext_b64 = base64.urlsafe_b64encode(ciphertext).decode()
            
            cipherdata = {
                'nonce': nonce_b64,
                'ciphertext': ciphertext_b64
            }
            
            with open(json_path, 'w') as file:
                json.dump(cipherdata, file, indent='\t')
            
            # Ahora genero un fichero que es donde guardaremos el cifrado de la clave simetrica con la clave publica del server
            keys_path = os.path.abspath('SERVER')
            keys_path += '/KEYS'
            simetric_key_path = os.path.join(keys_path, 'renting_simetric_encrypted_key.bin')
            
            # Abrimos el fichero que maneja la clave publica, para cifrar la clave simétrica
            with open(public_key_path, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
                )
            
            # Guardamos la clave simétrica cifrada en un archivo separado
            with open(simetric_key_path, 'wb') as key_file:
                key_file.write(Encryption.cifrar_clave_rsa(public_key, key))
        
        except Exception as e:
            print(f'Error al cifrar el fichero JSON. {e}')
            exit(1)

    @staticmethod
    def descifrar_users_json(json_path, private_key_path, simetric_key_path):
        """Esta función descifra el fichero BBDD_users.json con la clave simétrica que hemos cifrado asimétricamente
        en la función cifrar_users_json"""
        try:
            # Cargamos la clave privada RSA desde el archivo
            with open(private_key_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
                )
            
            # Cargamos la clave simétrica cifrada desde el archivo
            with open(simetric_key_path, 'rb') as key_file:
                encrypted_key = key_file.read()
            
            # Una vez cargamos la clave simétrica cifrada, eliminamos el archivo que la almacenaba
            os.remove(simetric_key_path)
            
            # Desciframos la clave simétrica utilizando la clave privada RSA
            key = Encryption.descifrar_clave_rsa(private_key, encrypted_key)
            
            # Cargamos el archivo cifrado
            with open(json_path, 'r') as file:
                cipherdata = json.load(file)
            
            # Desciframos el nonce y el ciphertext que estan guardados en el json
            nonce = base64.urlsafe_b64decode(cipherdata['nonce'])
            ciphertext = base64.urlsafe_b64decode(cipherdata['ciphertext'])
            
            # Desencriptamos el contenido encriptado del fichero json
            json_data = Encryption.descifrar_chacha20(key, nonce, ciphertext)
            
            # Pasamos el contenido de json de bytes a una lista
            data = json.loads(json_data)
            
            # Restauramos el archivo json con los datos que ya tenia 
            with open(json_path, 'w') as file:
                json.dump(data, file, indent='\t')
        
        except Exception as e:
            print(f'Error al descifrar el fichero JSON. {e}')
            exit(1)
             
    @staticmethod
    def descifrar_renting_json(json_path, private_key_path, simetric_key_path):
        """Esta función descifra el fichero BBDD_renting.json con la clave simétrica que hemos cifrado asimétricamente
        en la función cifrar_renting_json"""
        try:
            # Cargamos la clave privada RSA desde el archivo
            with open(private_key_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
                )
            
            # Cargamos la clave simétrica cifrada desde el archivo
            with open(simetric_key_path, 'rb') as key_file:
                encrypted_key = key_file.read()
            
            # Una vez cargamos la clave simétrica cifrada, eliminamos el archivo que la almacenaba
            os.remove(simetric_key_path)
            
            # Desciframos la clave simétrica utilizando la clave privada RSA
            key = Encryption.descifrar_clave_rsa(private_key, encrypted_key)
            
            # Cargamos el archivo cifrado
            with open(json_path, 'r') as file:
                cipherdata = json.load(file)
            
            # Desciframos el nonce y el ciphertext que estan guardados en el json
            nonce = base64.urlsafe_b64decode(cipherdata['nonce'])
            ciphertext = base64.urlsafe_b64decode(cipherdata['ciphertext'])
            
            # Desencriptamos el contenido encriptado del fichero json
            json_data = Encryption.descifrar_chacha20(key, nonce, ciphertext)
            
            # Pasamos el contenido de json de bytes a una lista
            data = json.loads(json_data)
            
            # Restauramos el archivo json con los datos que ya tenia 
            with open(json_path, 'w') as file:
                json.dump(data, file, indent='\t')
        
        except Exception as e:
            print(f'Error al descifrar el fichero JSON: {e}')
            exit(1)
        
    

   