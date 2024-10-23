import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization

class Encryption:
    # Método para generar par de claves RSA (pública y privada)
    @staticmethod
    def generar_claves_rsa():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    # Método para serializar y guardar la clave privada en un archivo
    @staticmethod
    def guardar_clave_privada(private_key, filepath):
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(filepath, 'wb') as f:
            f.write(pem)

    # Método para serializar y guardar la clave pública en un archivo
    @staticmethod
    def guardar_clave_publica(public_key, filepath):
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(filepath, 'wb') as f:
            f.write(pem)

    # Método para cargar la clave privada desde un archivo
    @staticmethod
    def cargar_clave_privada(filepath):
        with open(filepath, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        return private_key

    # Método para cargar la clave pública desde un archivo
    @staticmethod
    def cargar_clave_publica(filepath):
        with open(filepath, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return public_key

    # Cifrar la clave simétrica usando RSA (clave pública)
    @staticmethod
    def cifrar_key_rsa(key, public_key):
        encrypted_key = public_key.encrypt(
            key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key

    # Descifrar la clave simétrica usando RSA (clave privada)
    @staticmethod
    def descifrar_key_rsa(encrypted_key, private_key):
        decrypted_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_key

    # Método para derivar clave simétrica (igual al código anterior)
    @staticmethod
    def cifrar_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    # Método para cifrar datos (igual al código anterior)
    @staticmethod
    def cifrar_datos(data, key):
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data.encode())
        return encrypted_data

    # Método para descifrar datos (igual al código anterior)
    @staticmethod
    def descifrar_datos(encrypted_data, key):
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        return decrypted_data.decode()
