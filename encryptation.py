import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization

class Encryption:
    @staticmethod
<<<<<<< Updated upstream
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
    def cifrar_key(password, salt):
=======
    def token(password, salt):
>>>>>>> Stashed changes
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
        # Genera la etiqueta HMAC y la codifica en base64
        mac = base64.urlsafe_b64encode(h.finalize())
        return mac

    @staticmethod
    def verificar_hmac(data, key, mac):
        # Crea un objeto HMAC con la clave proporcionada y el algoritmo SHA-256
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        # Actualiza el objeto HMAC con los datos
        h.update(data.encode())
        try:
            # Verifica la etiqueta HMAC
            h.verify(base64.urlsafe_b64decode(mac))
            return True
        except InvalidSignature:
            return False