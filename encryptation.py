import base64  
from cryptography.fernet import Fernet  
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding  
from cryptography.hazmat.primitives import hmac 
from cryptography.exceptions import InvalidSignature 

class Encryption:
    @staticmethod
    def cifrar_key(password, salt):
        # Crea un objeto PBKDF2HMAC con el algoritmo SHA-256, longitud de clave de 32 bytes, sal y 100000 iteraciones
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),  
            length=32,  
            salt=salt,  
            iterations=100000,  
            backend=default_backend()  # Backend criptográfico por defecto
        )
        # Deriva la clave a partir de la contraseña y la codifica en base64
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key 

    @staticmethod
    def cifrar_datos(data, key):
        # Crea un objeto Fernet con la clave derivada
        fernet = Fernet(key)  
        # Cifra los datos y los devuelve
        encrypted_data = fernet.encrypt(data.encode())  
        return encrypted_data  

    @staticmethod
    def descifrar_datos(encrypted_data, key):
        # Crea un objeto Fernet con la clave derivada
        fernet = Fernet(key)  
        # Descifra los datos y los devuelve
        decrypted_data = fernet.decrypt(encrypted_data) 
        return decrypted_data.decode()  
    
    @staticmethod
    def generar_token(data):
        # Genera una clave Fernet
        key = Fernet.generate_key()
        fernet = Fernet(key)
        # Cifra los datos y devuelve el token y la clave
        token = fernet.encrypt(data.encode())
        return token, key

    @staticmethod
    def verificar_token(token, key):
        # Crea un objeto Fernet con la clave proporcionada
        fernet = Fernet(key)
        # Descifra el token y devuelve los datos
        data = fernet.decrypt(token)
        return data.decode()
    
    @staticmethod
    def generar_hmac(data, key):
        # Crea un objeto HMAC con la clave proporcionada y el algoritmo SHA-256
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        # Actualiza el objeto HMAC con los datos
        h.update(data.encode()) 
        # Crea un objeto Fernet con la clave derivada
        mac = h.finalize()  
        return base64.urlsafe_b64encode(mac)  # Devuelve la etiqueta HMAC codificada en base64

    @staticmethod
    def verificar_hmac(data, key, mac):
        # Crea un objeto HMAC con la clave proporcionada y el algoritmo SHA-256
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        # Crea un objeto Fernet con la clave derivada
        h.update(data.encode())  
        try:
            # Verifica la etiqueta HMAC proporcionada
            h.verify(base64.urlsafe_b64decode(mac))
            return True  # Devuelve True si la verificación es exitosa
        except InvalidSignature:
            return False  # Devuelve False si la verificación falla
