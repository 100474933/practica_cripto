import base64
import os
import json
import zlib 
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding 
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.hashes import SHA256
import tempfile
from filelock import FileLock


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
    def server_keys_and_certificate():
        # Creo una carpeta dentro de mi carpeta SERVER para guardar nuestras keys
        keys_path = os.path.abspath('SERVER')
        keys_path += '/keys_and_certificate'
        os.makedirs(keys_path, exist_ok=True)
        
        # Ahora junto la ruta de mi carpeta keys con los archivos que contienen las keys y el certificado
        private_key_path = os.path.join(keys_path, 'private_key.pem')
        public_key_path = os.path.join(keys_path, 'public_key.pem')
        certificate_path = os.path.join(keys_path, 'certificate.pem')
        
        # Verificamos que no se hayan creado ya las claves y el certificado del server
        if not os.path.exists(private_key_path) and not os.path.exists(public_key_path):
            # Generamos un par de claves RSA para el server, una pública y otra privada
            private_key, public_key = Encryption.generar_claves_rsa()
            
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
            
            # Antes de crear el certificado necesitamos el certificado de la autoridad que nos certifica y su clave pública
            ca_path = os.path.abspath('ACs')
            ca_path += '/AC_Commerce'
            ca_cert_path = ca_path + '/certificate.pem'
            
            with open(ca_cert_path, "rb") as f:
                ca_certificate_data = f.read()
            
            ca_cert = x509.load_pem_x509_certificate(ca_certificate_data, default_backend())
            ca_private_key_path = ca_path + '/private_key.pem'
            with open(ca_private_key_path, "rb") as f:
                ca_private_key = load_pem_private_key(f.read(), password=None)

            # Ahora crearemos el certificado del usuario, autenticado por el Ministerio de Comercio
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Comunidad de Madrid"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'ServerMaríaAlex'),
            ])
            user_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                # Our cert will be valid for 180 days
                datetime.now(timezone.utc) + timedelta(days=180)
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
                ),
                critical=False,
            ).sign(ca_private_key, hashes.SHA256())
            
            # Guardamos el certificado en un archivo separado
            with open(certificate_path, "wb") as cert_file:
                cert_file.write(user_cert.public_bytes(Encoding.PEM))

    @staticmethod
    def user_keys_and_certificate(name):
        # Creo una carpeta para almacenar las keys y el certificado de mi usuario
        keys_path = os.path.abspath('USERS')
        keys_path += f'/{name}'
        os.makedirs(keys_path, exist_ok=True)
        
        
        # Ahora junto la ruta de mi carpeta keys con los archivos que contienen las keys
        private_key_path = os.path.join(keys_path, 'private_key.pem')
        public_key_path = os.path.join(keys_path, 'public_key.pem')
        certificate_path = os.path.join(keys_path, 'certificate.pem')
        
        if not os.path.exists(private_key_path) and not os.path.exists(public_key_path):
            # Generamos un par de claves RSA para el usuario, una pública y otra privada
            private_key, public_key = Encryption.generar_claves_rsa()
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
            
            # Antes de crear el certificado necesitamos el certificado de la autoridad que certifica a los usuarios y su clave pública
            ca_path = os.path.abspath('ACs')
            ca_path += '/AC_Transport'
            ca_cert_path = ca_path + '/certificate.pem'
            
            with open(ca_cert_path, "rb") as f:
                ca_certificate_data = f.read()
            
            ca_cert = x509.load_pem_x509_certificate(ca_certificate_data, default_backend())
            ca_private_key_path = ca_path + '/private_key.pem'
            with open(ca_private_key_path, "rb") as f:
                ca_private_key = load_pem_private_key(f.read(), password=None)
            
            # Ahora crearemos el certificado del usuario, autenticado por el Ministerio de Transportes
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Comunidad de Madrid"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, name),
            ])
            user_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                # El certificado sera válido por 180 días
                datetime.now(timezone.utc) + timedelta(days=180)
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
                ),
                critical=False,
            ).sign(ca_private_key, hashes.SHA256())
            
            # Guardamos el certificado en un archivo separado
            with open(certificate_path, "wb") as cert_file:
                cert_file.write(user_cert.public_bytes(Encoding.PEM))

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
            keys_path += '/keys_and_certificate'
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
            print(f'Error al cifrar el fichero JSON. Los datos fueron alterados. {e}')
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
            keys_path = os.path.abspath('SERVER/keys_and_certificate')
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
            print(f'Error al cifrar el fichero JSON. Los datos fueron alterados. {e}')
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
            print(f'Error al descifrar el fichero JSON. Los datos fueron alterados. {e}')
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
            print(f'Error al descifrar el fichero JSON. Los datos fueron alterados. {e}')
            exit(1)
             
    @staticmethod
    def crear_estructura_PKI():
        # Lo primero es comprobar si la estructura esta ya creada
        root_path = os.path.abspath('ACs')
        root_path += '/AC_Root'
        if not os.path.exists(root_path):
            # Primero crearemos una autoridad raiz, el gobierno español en nuestro caso. Le generamos dos claves RSA
            root_private_key, root_public_key = Encryption.generar_claves_rsa()
            
            # Creamos una carpeta para guardar las claves y certificado de la autoridad raiz
            os.makedirs(root_path, exist_ok=True)
            
            root_private_key_path = os.path.join(root_path, 'private_key.pem')
            root_public_key_path = os.path.join(root_path, 'public_key.pem')
            root_certificate_path = os.path.join(root_path, 'certificate.pem')
            
            # Guardamos la clave privada en un archivo separado
            with open(root_private_key_path, 'wb') as key_file:
                        key_file.write(root_private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        ))
            
            # Guardamos la clave pública en un archivo separado
            with open(root_public_key_path, 'wb') as key_file:
                        key_file.write(root_public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ))
            
            # Ahora creamos el certificado de clave
            # El subject (dueño del certificado) es el gobierno, y el issuer (emisor del certificado), tambien es 
            # el gobierno, ya que se certifica a si mismo
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Comunidad de Madrid"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Gobierno de España"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Raiz CA"),
            ])
            
            root_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                root_public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                # El certificado será válido por 4 años
                datetime.now(timezone.utc) + timedelta(days=365*4)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(root_public_key),
                critical=False,
            ).sign(root_private_key, hashes.SHA256())
            
            # Guardamos el certificado en un archivo separado
            with open(root_certificate_path, "wb") as cert_file:
                cert_file.write(root_cert.public_bytes(Encoding.PEM))
            
            # Despues generamos nuestras otras dos entidades certificadoras, el ministerio de Comercio, que certificará al server y el ministerio de Transporte, que certificará a los usuarios
            
            # Certificado Ministerio de Comercio
            comerce_private_key, comerce_public_key = Encryption.generar_claves_rsa()
            
            # Primero creamos y almacenamos las claves RSA de la autoridad de comercio
            comerce_path = os.path.abspath('ACs')
            comerce_path += '/AC_Commerce'
            os.makedirs(comerce_path, exist_ok=True)
            
            comerce_private_key_path = os.path.join(comerce_path, 'private_key.pem')
            comerce_public_key_path = os.path.join(comerce_path, 'public_key.pem')
            comerce_certificate_path = os.path.join(comerce_path, 'certificate.pem')
            
            # Guardamos la clave privada en un archivo separado
            with open(comerce_private_key_path, 'wb') as key_file:
                        key_file.write(comerce_private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        ))
            
            # Guardamos la clave pública en un archivo separado
            with open(comerce_public_key_path, 'wb') as key_file:
                        key_file.write(comerce_public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ))
            # Ahora creamos el certificado de clave
            
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Comunidad de Madrid"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ministerio de Comercio"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Certificador server"),
            ])
            
            comerce_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                root_cert.subject
            ).public_key(
                comerce_public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                # El certificado será válido por 1 año
                datetime.now(timezone.utc) + timedelta(days=365)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(comerce_public_key),
                critical=False,
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
                ),
                critical=False,
            ).sign(root_private_key, hashes.SHA256())
            
            # Guardamos el certificado de clave
            with open(comerce_certificate_path, "wb") as cert_file:
                cert_file.write(comerce_cert.public_bytes(Encoding.PEM))
            
            # Certificado Ministerio de Transportes
                    
            transport_private_key, transport_public_key = Encryption.generar_claves_rsa()
            
            # Primero creamos y almacenamos las claves RSA de la autoridad de transporte
            transport_path = os.path.abspath('ACs')
            transport_path += '/AC_Transport'
            os.makedirs(transport_path, exist_ok=True)
            
            transport_private_key_path = os.path.join(transport_path, 'private_key.pem')
            transport_public_key_path = os.path.join(transport_path, 'public_key.pem')
            transport_certificate_path = os.path.join(transport_path, 'certificate.pem')
            
            # Guardamos la clave privada en un archivo separado
            with open(transport_private_key_path, 'wb') as key_file:
                        key_file.write(transport_private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        ))
            
            # Guardamos la clave pública en un archivo separado
            with open(transport_public_key_path, 'wb') as key_file:
                        key_file.write(transport_public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ))
            
            # Ahora creamos el certificado de clave
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Comunidad de Madrid"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ministerio de Transportes"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Certificador users"),
            ])
            
            transport_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                root_cert.subject
            ).public_key(
                transport_public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                # El certificado será válido por 1 año
                datetime.now(timezone.utc) + timedelta(days=365)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(transport_public_key),
                critical=False,
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
                ),
                critical=False,
            ).sign(root_private_key, hashes.SHA256())
            
            # Guardamos el certificado de clave
            with open(transport_certificate_path, "wb") as cert_file:
                cert_file.write(transport_cert.public_bytes(Encoding.PEM))
    
    @staticmethod
    def verificar_certificado(cert, parent_cert):
        try:
            parent_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),  # Asegúrate de usar el padding correcto
                hashes.SHA256()  # Cambia SHA256 por el hash que corresponda
            )
            if cert.not_valid_before_utc <= datetime.now(timezone.utc) <= cert.not_valid_after_utc:
                return True
            return False
        except InvalidSignature:
            print('\nError: firma digital incorrecta.')

    @staticmethod
    def verificacion_certificados_usuario(name):
        try:
            # Cargar certificados
            user_cert_path = os.path.join('USERS', name, 'certificate.pem')
            with open(user_cert_path, "rb") as f:
                user_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            ca_cert_path = os.path.join('ACs', 'AC_Transport', 'certificate.pem')
            with open(ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            root_cert_path = os.path.join('ACs', 'AC_Root', 'certificate.pem')
            with open(root_cert_path, "rb") as f:
                root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            # Verificar validez de los certificados

            user_status = Encryption.verificar_certificado(user_cert, ca_cert)
            ca_status = Encryption.verificar_certificado(ca_cert, root_cert)

            if user_status and ca_status:
                print('\nCertificados de usuario verificados.')
            else:
                print('\nLos certificados de usuario no puedieron ser validados.')


        except FileNotFoundError as e:
            print(f"Error: Archivo no encontrado - {e}")
        except Exception as e:
            print(f"Error inesperado: {e}")

    @staticmethod
    def verificacion_certificados_server():
        # Cargamos los certificados del usuario, de su autoridad certificadora y de la autoridad raíz
        
        try:
            # Cargar certificados
            server_cert_path = os.path.join('SERVER', 'keys_and_certificate', 'certificate.pem')
            with open(server_cert_path, "rb") as f:
                server_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            ca_cert_path = os.path.join('ACs', 'AC_Commerce', 'certificate.pem')
            with open(ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            root_cert_path = os.path.join('ACs', 'AC_Root', 'certificate.pem')
            with open(root_cert_path, "rb") as f:
                root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            # Verificar validez de los certificados

            server_status = Encryption.verificar_certificado(server_cert, ca_cert)
            ca_status = Encryption.verificar_certificado(ca_cert, root_cert)

            if server_status and ca_status:
                print('\nCertificados de servidor verificados.')
            else:
                print('\nLos certificados de servidor no puedieron ser validados.')


        except FileNotFoundError as e:
            print(f"Error: Archivo no encontrado - {e}")
        except Exception as e:
            print(f"Error inesperado: {e}")

    @staticmethod
    def dividir_y_cifrar_json(package_json, ku):
        # Dividir el JSON en fragmentos de tamaño adecuado (ejemplo: 190 bytes)
        max_fragment_size = 190  # Ajustar según el tamaño de la clave pública RSA
        fragments = [
            package_json[i:i + max_fragment_size]
            for i in range(0, len(package_json), max_fragment_size)
        ]

        # Cifrar cada fragmento con RSA
        encrypted_fragments = [
            ku.encrypt(
                fragment.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            for fragment in fragments
        ]

        return encrypted_fragments

    @staticmethod
    def crear_clave_sesion(name):
        try:
            # Generar clave de sesión aleatoria de 32 bytes
            ks = os.urandom(32)

            # Generar un hash de la clave de sesión
            digest = hashes.Hash(hashes.SHA256())
            digest.update(ks)
            hashed_ks = digest.finalize()

            # Cargar la clave privada del servidor
            private_key_path = os.path.abspath('SERVER/keys_and_certificate/private_key.pem')
            with open(private_key_path, 'rb') as f:
                kp = load_pem_private_key(f.read(), password=None)

            # Firmar el hash con la clave privada
            signature = kp.sign(
                hashed_ks,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Cargar la clave pública del usuario
            public_key_path = os.path.abspath(f'USERS/{name}/public_key.pem')
            with open(public_key_path, "rb") as f:
                ku = load_pem_public_key(f.read())

            # Codificar valores en Base64 para JSON
            package = {
                'session_key': base64.b64encode(ks).decode('utf-8'),
                'signature': base64.b64encode(signature).decode('utf-8')
            }

            # Convertir el paquete a JSON
            package_json = json.dumps(package)
            
            # Dividimos el json en fragmnetos, para que pueda ser encriptado
            encrypted_fragments = Encryption.dividir_y_cifrar_json(package_json, ku)
           
            print('\nGenerando la clave de sesión.')
            return encrypted_fragments

        except FileNotFoundError as e:
            print(f"Error: Archivo no encontrado - {e}")
            return None
        except ValueError as e:
            print(f"Error de valor: {e}")
            return None
        except TypeError as e:
            print(f"Error de tipo: {e}")
            return None
        except Exception as e:
            print(f"Error inesperado: {e}")
            return None

    @staticmethod
    def reconstruir_paquete(encrypted_fragments, private_key):
        try:
            # Desencriptar cada fragmento usando la clave privada
            decrypted_fragments = [
                private_key.decrypt(
                    fragment,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=SHA256()),
                        algorithm=SHA256(),
                        label=None
                    )
                )
                for fragment in encrypted_fragments
            ]

            # Reconstruir el paquete original uniendo los fragmentos
            reconstructed_package = b''.join(decrypted_fragments)

            # Convertir el paquete a JSON
            package_json = reconstructed_package.decode()
            package = json.loads(package_json)

            return package

        except Exception as e:
            print(f"Error al reconstruir el paquete: {e}")
            return None
    
    @staticmethod
    def validar_clave_sesion(encrypted_fragments, name):
        try:
            print('\nValidando clave de sesión, espere unos segundos')

            # Cargar la clave privada del usuario
            private_key_path = os.path.abspath(f'USERS/{name}/private_key.pem')
            with open(private_key_path, "rb") as f:
                user_private_key = load_pem_private_key(f.read(), password=None)  # Usa una contraseña en producción

            # Usamos la función reconstruir_paquete para descrifrar y juntar los fragemtos del paquete original
            package = Encryption.reconstruir_paquete(encrypted_fragments, user_private_key)
            
            session_key = base64.b64decode(package['session_key'])  # Decodificar de Base64
            signature = base64.b64decode(package['signature'])  # Decodificar de Base64

            # Cargar la clave pública del servidor
            public_key_path = os.path.abspath('SERVER/keys_and_certificate/public_key.pem')
            with open(public_key_path, "rb") as f:
                server_public_key = load_pem_public_key(f.read())

            # Generar el hash de la clave de sesión
            digest = hashes.Hash(hashes.SHA256())
            digest.update(session_key)
            hashed_ks = digest.finalize()

            # Verificar la firma
            server_public_key.verify(
                signature,
                hashed_ks,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print('\nClave de sesión validada.')

            # Guardar la clave de sesión en el servidor y en el usuario
            ks_server_path = os.path.join(os.path.abspath('SERVER/keys_and_certificate'), 'session_key.bin')
            ks_user_path = os.path.join(os.path.abspath(f'USERS/{name}'), 'session_key.bin')

            try:
                with open(ks_server_path, "wb") as f:
                    f.write(session_key)
                with open(ks_user_path, "wb") as f:
                    f.write(session_key)
                print('\nClave de sesión guardada correctamente.')
            except IOError as e:
                print(f"Error al guardar la clave de sesión: {e}")

        except InvalidSignature:
            print("\nLa firma del servidor no pudo ser validada.")
        except ValueError as e:
            print(f"\nError al descifrar el paquete o procesar JSON: {e}")
        except FileNotFoundError as e:
            print(f"\nArchivo no encontrado: {e}")
        except Exception as e:
            print(f"\nError inesperado: {e}")

    @staticmethod
    def get_session_key(client=False, username=None):
        """Obtiene la clave de sesión para el servidor o el cliente."""
        if client and username:
            session_key_path = os.path.abspath(f'USERS/{username}/session_key.bin')
        else:
            session_key_path = os.path.abspath('SERVER/keys_and_certificate/session_key.bin')

        if os.path.exists(session_key_path):
            with open(session_key_path, "rb") as f:
                return f.read()
        else:
            raise FileNotFoundError("No se encontró la clave de sesión.")

    @staticmethod
    def get_private_key(client=False, username=None):
        """Obtiene la clave privada del servidor o del cliente."""
        if client and username:
            private_key_path = os.path.abspath(f'USERS/{username}/private_key.pem')
        else:
            private_key_path = os.path.abspath('SERVER/keys_and_certificate/private_key.pem')

        if os.path.exists(private_key_path):
            with open(private_key_path, "rb") as f:
                return load_pem_private_key(f.read(), password=None)
        else:
            raise FileNotFoundError("No se encontró la clave privada.")

    @staticmethod
    def get_public_key(client=False, username=None):
        """Obtiene la clave pública del servidor o del cliente."""
        if client and username:
            public_key_path = os.path.abspath(f'USERS/{username}/public_key.pem')
        else:
            public_key_path = os.path.abspath('SERVER/keys_and_certificate/public_key.pem')

        if os.path.exists(public_key_path):
            with open(public_key_path, "rb") as f:
                return load_pem_public_key(f.read())
        else:
            raise FileNotFoundError("No se encontró la clave pública.")

    @staticmethod
    def encrypt_message(message: str, client=False, username=None):
        """Cifra un mensaje con la clave de sesión y firma el hash."""
        print(f"[INFO] Cifrando mensaje{' para el cliente' if client else ''}...")
        try:
            session_key = Encryption.get_session_key(client, username)
            private_key = Encryption.get_private_key(client, username)

            # Calcular el hash del mensaje
            digest = hashes.Hash(hashes.SHA256())
            digest.update(message.encode('utf-8'))
            message_hash = digest.finalize()

            # Firmar el hash del mensaje con la clave privada
            signature = private_key.sign(
                message_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Adjuntar la firma al mensaje y cifrar todo con la clave de sesión
            message_with_signature = json.dumps({
                "message": message,
                "signature": base64.b64encode(signature).decode('utf-8')
            }).encode('utf-8')

            # Cifrar usando ChaCha20Poly1305
            chacha = ChaCha20Poly1305(session_key)
            nonce = os.urandom(12)
            ciphertext = chacha.encrypt(nonce, message_with_signature, None)

            print("[INFO] Mensaje cifrado exitosamente.")
            return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}
        except Exception as e:
            raise ValueError(f"Error al cifrar el mensaje: {e}")

    @staticmethod
    def decrypt_message(encrypted_data: dict, client=False, username=None):
        """Descifra un mensaje cifrado y verifica la firma."""
        print(f"[INFO] Descifrando mensaje{' para el cliente' if client else ''}...")
        try:
            session_key = Encryption.get_session_key(client, username)
            public_key = Encryption.get_public_key(client, username)

            # Descifrar con ChaCha20Poly1305
            chacha = ChaCha20Poly1305(session_key)
            nonce = bytes.fromhex(encrypted_data['nonce'])
            ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
            message_with_signature = chacha.decrypt(nonce, ciphertext, None)

            # Separar mensaje y firma
            message_data = json.loads(message_with_signature.decode('utf-8'))
            message = message_data["message"]
            signature = base64.b64decode(message_data["signature"])

            # Calcular el hash del mensaje
            digest = hashes.Hash(hashes.SHA256())
            digest.update(message.encode('utf-8'))
            message_hash = digest.finalize()

            # Verificar la firma usando la clave pública
            public_key.verify(
                signature,
                message_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            print("[INFO] Mensaje descifrado y verificado exitosamente.")
            return message
        except Exception as e:
            raise ValueError(f"Error al descifrar o verificar el mensaje: {e}")
        