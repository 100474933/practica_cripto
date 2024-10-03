from DataBase import DataBase
import os
import BBDD

class Text:

    @staticmethod
    def loading():
        print("\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n")

    @staticmethod
    def inicial():

        # Pantalla de carga
        Text.loading()

        # Imprimiendo mensajes de bienvenida
        print("\n------------------------------¡BIENVENIDO AL ALQUILER DE COCHES!---------------------------- \n")
        print("\n1 - CREAR NUEVA CUENTA (INTRODUCE 1)")
        print("\n2 - INICIAR SESIÓN (INTRODUCE 2)")
        print("\n3 - SALIR DEL PROGRAMA (INTRODUCE 3)")

        # Pantalla de carga
        Text.loading()
        # Input del usuario
        command = input("\nINPUT: ")

        # Ejecutando programa según el input introducido
        if command == "1":
            # Nueva cuenta
            Text.Registo()
        elif command == "2":
            # Login de cuenta
            Text.IniciarSesion()
        else:
            # Salir del programa
            Text.quit_program()
    def Registo():
        # Pantalla de carga
        Text.loading()

        # Imprimiendo mensajes de bienvenida
        print("\n------------------------------¡CREAR NUEVA CUENTA!---------------------------- \n")

        # Pantalla de carga
        Text.loading()

        # Input del usuario
        name = input("\nIntroduce tu nombre: ")
        password = input("\nIntroduce tu contraseña: ")

        # Creando nueva cuenta
        DataBase.create_account(name, password)

        # Pantalla de carga
        Text.loading()

        # Mensaje de cuenta creada
        print("\n------------------------------¡CUENTA CREADA CON ÉXITO!---------------------------- \n")

        # Pantalla de carga
        Text.loading()

        # Volviendo al estado inicial
        Text.inicial()

    def IniciarSesion():
        # Pantalla de carga
        Text.loading()

        # Imprimiendo mensajes de bienvenida
        print("\n------------------------------¡INICIAR SESIÓN!---------------------------- \n")

        # Pantalla de carga
        Text.loading()

        # Input del usuario
        nombre = input("\nIntroduce tu nombre: ")
        password = input("\nIntroduce tu contraseña: ")

        # Iniciando sesión
        DataBase.login(nombre, password)

        # Pantalla de carga
        Text.loading()

        # Mensaje de sesión iniciada
        print("\n------------------------------¡SESIÓN INICIADA CON ÉXITO!---------------------------- \n")

        # Pantalla de carga
        Text.loading()

        # Volviendo al estado inicial
        Text.inicial()
    
    def quit_program():
        # Pantalla de carga
        Text.loading()

        # Imprimiendo mensajes de despedida
        print("\n------------------------------¡GRACIAS POR UTILIZAR NUESTRO SERVICIO!---------------------------- \n")

        # Pantalla de carga
        Text.loading()

        # Saliendo del programa
        os._exit(0)

