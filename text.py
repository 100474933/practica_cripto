import os
from renting import Renting
from users import Users
from encryptation import Encryption

class Text:

    @staticmethod
    def loading():
        print("-"*150)
    
    @staticmethod
    def welcoming():
        # Creo una carpeta para almacenar a mis usuarios, sus claves y certificado
        os.makedirs('USERS', exist_ok=True)
        
        # Creo una carpeta para almacerna las autoridades certificadoras
        os.makedirs('ACs', exist_ok=True)
        
        # Creo una carpeta para almacenra las claves y certificado de mi server, asi como las bases de datos
        os.makedirs('SERVER', exist_ok=True)
        
        # Creando la BBDD del SERVER
        Users.create_BBDD()

        # Creamos las autoridades certificadoras, sus claves y certificados
        Encryption.crear_estructura_PKI()
        
        # Creamos el certificado del server y sus claves RSA
        Encryption.server_keys_and_certificate()
        
        Text.loading()
        # Imprimiendo mensajes de bienvenida
        print("  ____  _                           _     _               _            _             _ _                 _         _____           _               ")
        print(" |  _ \(_)                         (_)   | |             | |     /\   | |           (_) |               | |       / ____|         | |              ")
        print(" | |_) |_  ___ _ ____   _____ _ __  _  __| | ___     __ _| |    /  \  | | __ _ _   _ _| | ___ _ __    __| | ___  | |     ___   ___| |__   ___  ___ ")
        print(" |  _ <| |/ _ \ '_ \ \ / / _ \ '_ \| |/ _` |/ _ \   / _` | |   / /\ \ | |/ _` | | | | | |/ _ \ '__|  / _` |/ _ \ | |    / _ \ / __| '_ \ / _ \/ __|")
        print(" | |_) | |  __/ | | \ V /  __/ | | | | (_| | (_) | | (_| | |  / ____ \| | (_| | |_| | | |  __/ |    | (_| |  __/ | |___| (_) | (__| | | |  __/\__ \ ")
        print(" |____/|_|\___|_| |_|\_/ \___|_| |_|_|\__,_|\___/   \__,_|_| /_/    \_\_|\__, |\__,_|_|_|\___|_|     \__,_|\___|  \_____\___/ \___|_| |_|\___||___/")
        print("                                                                            | |                                                                   ")
        print("                                                                            |_|                                                                   ")
        print("----------------------------------------------------¡ALQUILER 24 HORAS DE LUNES A DOMINGOS!--------------------------------------------------------")
        Text.loading()

    @staticmethod
    def inicial():

        print("  __  __ ______ _   _ _    _  ")
        print(" |  \/  |  ____| \ | | |  | | ")
        print(" | \  / | |__  |  \| | |  | | ")
        print(" | |\/| |  __| | . ` | |  | | ")
        print(" | |  | | |____| |\  | |__| | ")
        print(" |_|  |_|______|_| \_|\____/  ")
        
        print("\n1 - CREAR NUEVA CUENTA (INTRODUCE 1)")
        print("\n2 - INICIAR SESIÓN (INTRODUCE 2)")
        print("\n3 - SALIR DEL PROGRAMA (INTRODUCE 3)")

        # Pantalla de carga
        Text.loading()
        # Input del usuario
        command = input("\nELIGE UNA OPCIÓN PARA CONTINUAR: ")

        # Ejecutando programa según el input introducido
        if command == "1":
            # Nueva cuenta
            Text.registro()
        elif command == "2":
            # Login de cuenta
            Text.login()
        else:
            # Salir del programa
            Text.quit_program()
    
    @staticmethod
    def registro():        
        # Pantalla de carga
        Text.loading()
        
        # Creando nueva cuenta
        Users.create_account()
        
        # Pantalla de carga
        Text.loading()

        # Mensaje de cuenta creada
        print("\n--------------------------------------------------------------¡CUENTA CREADA CON ÉXITO!---------------------------------------------------------------\n")

        # Pantalla de carga
        Text.loading()

        # Volviendo al estado inicial
        Text.inicial()

    @staticmethod
    def login():
        # Pantalla de carga
        Text.loading()

        # Input del usuario
        nombre = input("\nINTRODUCE TU NOMBRE: ")
        password = input("\nINTRODUCE TU CONTRASEÑA: ")

        # Iniciando sesión
        try:
            Users.login(nombre, password)
        except ValueError as e:
            print(e)
        
        # Validando certificados del usuario
        Encryption.verificacion_certificados_usuario(nombre)
        Encryption.verificacion_certificados_server()
        
        # Creando una clave de sesión
        ks_fragemnts = Encryption.crear_clave_sesion(nombre)
        Encryption.validar_clave_sesion(ks_fragemnts, nombre)

        # Pantalla de carga
        Text.loading()

        # Mensaje de sesión iniciada
        print("\n--------------------------------------------------------------¡SESIÓN INICIADA CON ÉXITO!---------------------------------------------------------------\n")

        # Pantalla de carga
        Text.loading()
        
        # Cargando el menu
        Renting.menu(nombre)
        
        # Cuando acabe cerramos la sesion
        Users.logout(nombre)
        
        # Volvemos al menu inicial
        Text.inicial()
    
    @staticmethod
    def quit_program():
        # Pantalla de carga
        Text.loading()

        # Imprimiendo mensajes de despedida
        print("   _____                _                                                       _                            ")
        print("  / ____|              (_)                                                     | |                           ")
        print(" | |  __ _ __ __ _  ___ _  __ _ ___   _ __   ___  _ __   _   _ ___  __ _ _ __  | | __ _    __ _ _ __  _ __   ")
        print(" | | |_ | '__/ _` |/ __| |/ _` / __| | '_ \ / _ \| '__| | | | / __|/ _` | '__| | |/ _` |  / _` | '_ \| '_ \  ")
        print(" | |__| | | | (_| | (__| | (_| \__ \ | |_) | (_) | |    | |_| \__ \ (_| | |    | | (_| | | (_| | |_) | |_) | ")
        print("  \_____|_|  \__,_|\___|_|\__,_|___/ | .__/ \___/|_|     \__,_|___/\__,_|_|    |_|\__,_|  \__,_| .__/| .__/  ")
        print("                                     | |                                                       | |   | |     ")
        print("                                     |_|                                                       |_|   |_|     ")
        
        # Pantalla de carga
        Text.loading()

        # Saliendo del programa
        os._exit(0)

Text.welcoming()
Text.inicial()