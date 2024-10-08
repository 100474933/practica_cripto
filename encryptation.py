from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.backends import default_backend
import os

class Encryption:
    @staticmethod
    def cifrar_key(password, salt):

        # Se crea un objeto PBKDF2HMAC con el algoritmo SHA256, una longitud de clave de 32 bytes, la sal generada y 100000 iteraciones.
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        # Se deriva la clave a partir de la contraseña.
        key = kdf.derive(password.encode())
        return key

    @staticmethod
    def cifrar_datos(data, key):
        iv = os.urandom(16) # Vector de inicialización
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) # Cifrado simétrico
        encryptor = cipher.encryptor() # Cifrador
        
        # Añadimos padding a los datos,  Esto es necesario porque el algoritmo AES en modo CBC requiere que los datos tengan una longitud específica
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        
        # Ciframos los datos
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    @staticmethod
    def descifrar_datos(ciphertext, key):
        #Se extraen los primeros 16 bytes del texto cifrado, que corresponden al IV utilizado durante el cifrado.
        iv = ciphertext[:16]
        
        #Se extrae el resto del texto cifrado, que es el texto cifrado real sin el IV.
        actual_ciphertext = ciphertext[16:]

        #Se crea un objeto Cipher con el algoritmo AES, el modo CBC y el IV extraído.
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        #Se crea un objeto Decryptor para descifrar los datos.
        decryptor = cipher.decryptor()

        #Se crea un objeto Unpadder para eliminar el padding de los datos descifrados.
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        #Se descifran los datos y se eliminan los bytes de padding.
        padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        #Se devuelve el texto plano descifrado.
        return plaintext.decode()