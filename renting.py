
import json
import os
from datetime import datetime, timedelta
from encryptation import Encryption




class Renting:
    
    @staticmethod
    def loading():
        print("-"*150)
        
    @staticmethod
    def save_data(data):
        # Obtenemos la ruta donde guardamos los datos
        db_file_path = os.path.abspath('SERVER')
        db_file_path += '/BBDD/BBDD_renting.json'
        
        try:
            # Abrimos el fichero de datos y los guardamos
            with open(db_file_path, 'w') as bbdd_file:
                data = json.dump(data, bbdd_file, indent='\t')
            
            # Ahora procedemos a encriptar el fichero, para ello necesitaremos la clave publica del SERVER
            public_key_path = os.path.abspath('SERVER')
            public_key_path += '/KEYS/server_public_key.pem'
            
            # Encriptamos el fichero
            Encryption.cifrar_renting_json(db_file_path, public_key_path)
        
        except Exception as e:
            print(f'{e}')
    
    @staticmethod   
    def load_data():
        db_file_path = os.path.abspath('SERVER')
        db_file_path += '/BBDD/BBDD_renting.json'
        if os.path.exists(db_file_path):
            try:
                # Obtenemos las rutas de los ficheros que guardan la clave privada y la encriptación de la clave simetrica
                private_key_path = os.path.abspath('SERVER')
                simetric_key_path = private_key_path
                private_key_path += '/KEYS/server_private_key.pem' 
                simetric_key_path += '/KEYS/renting_simetric_encrypted_key.bin'
                
                # Desencriptamos la base de datos
                Encryption.descifrar_renting_json(db_file_path, private_key_path, simetric_key_path)
                
                # Una vez desencriptado la base de datos entramos y leemos los datos
                with open(db_file_path, 'r') as data:
                    content = data.read().strip()  # Leemos el archivo y eliminamos espacios en blanco
                    if content:  # Solo intentamos cargar el JSON si hay contenido
                        return json.loads(content)
            except json.JSONDecodeError:
                print("El archivo de datos está corrupto. Iniciando una base de datos vacía.")
            except Exception as e:
                print(f"Error al leer el archivo: {e}")
        return []
    
    @staticmethod
    def start_secure_session(user_public_key_path):
        # Genera una clave de sesión temporal
        session_key = Encryption.generar_key_chacha20()
        
        # Cifra la clave de sesión temporal con la clave pública del usuario
        with open(user_public_key_path, 'rb') as key_file:
            user_public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        
        encrypted_session_key = Encryption.cifrar_clave_rsa(user_public_key, session_key)
        return session_key, encrypted_session_key

    @staticmethod
    def time_in_out():
        # Está función comprueba si un coche esta alquilado en el momento actual o no
        try:
            data = Renting.load_data()
            actual_date = datetime.now()
            # Comprobamos para cada reserva si existe la key 'return_time' y la key 'rent_time'
            for car in data:
                if 'return_time' in car and 'rent_time' in car:
                    return_time = car['return_time']
                    rent_time = car['rent_time']
                    return_time_obj = datetime.strptime(return_time, "%d/%m/%Y %H:%M:%S")
                    rent_time_obj = datetime.strptime(rent_time, "%d/%m/%Y %H:%M:%S")
                    
                    # Ahora establecemos si el coche esta alquilado o no, dependiendo de la fecha actual
                    if rent_time_obj <= actual_date:
                        car['rented'] = True
                        if return_time_obj <= actual_date:
                            car['rented'] = False
                    
            
            # Guardamos los datos y los encriptamos
            Renting.save_data(data)
        
        except Exception as e:
            print(f'{e}')
    
    @staticmethod
    def menu(name):
        #Cada vez que iniciamos sesion se actualiza el estado de renting de los coches
        Renting.time_in_out()
        cond = False
        
        print("  _____   ____   ____  __ __  /\ ")
        print(" /     \_/ __ \ /    \|  |  \ \/ ")
        print("|  Y Y  \  ___/|   |  \  |  / /\ ")
        print("|__|_|  /\___  >___|  /____/  \/ ")
        print("      \/     \/     \/           ")

        print("    ______             ______             ______                ______                     ______         ")
        print("   /|_||_\\`.__       /|_||_\\`.__       /|_||_\\`.__          /|_||_\\`.__               /|_||_\\`.__      ")
        print("  (   _    _ _ \\    (   _    _ _ \\    (   _    _ _ \\       (   _    _ _ \\            (   _    _ _ \\   ")
        print("  =`-(_)--(_)-'      =`-(_)--(_)-'      =`-(_)--(_)-'         =`-(_)--(_)-'              =`-(_)--(_)-'   ")
        print("------------------>------------------->------------------>------------------------->------------------>")
        print(" |    AUDI X5       |  TOYOTA YARIS   |    BMW 320D       |    MITSUBISHI MONTERO   |    SMART BRABUS   |")

        
        print("\n1 - RESERVAR COCHES")
        print("\n2 - MIS RESERVAS")
        print("\n3 - CERRAR SESIÓN")
        
        command = int(input("\nELIGE UNA OPCIÓN PARA CONTINUAR: "))
        print(command)
        
        while not cond:
            Renting.loading()
            
            if command == 1:
                cond = True
                Renting.reserve_menu(name)
            elif command == 2:
                cond = True
                Renting.user_reservations(name)
            elif command == 3:
                cond = True
            else: 
                command = input("\nLAS OPCIONES SON LAS QUE APARECEN EN EL MENU(1, 2 y 3).ELIGE UNA OPCIÓN PARA CONTINUAR: ")
                Renting.menu(name)
    
    @staticmethod
    def reserve_menu(name):
        cond = False
        print("------------- SELECCIONE EL TIPO DE COCHE -------------")
        print("\n1 - AUDI X5")
        print("\n2 - TOYOTA YARIS")
        print("\n3 - BMW 320D")
        print("\n4 - MITSUBISHI MONTERO")
        print("\n5 - SMART BRABUS")
        
        command = int(input("\nELIGE UNA OPCIÓN PARA CONTINUAR: "))
        
        while not cond:
            Renting.loading()
            
            if command == 1:
                cond = True
                car='AUDI X5'
                Renting.reserve(name, car)
            elif command == 2:
                cond = True
                car='TOYOTA YARIS'
                Renting.reserve(name, car)
            elif command == 3:
                cond = True
                car='BMW 320D'
                Renting.reserve(name, car)
            elif command == 4:
                cond = True 
                car='MITSUBISHI MONTERO'
                Renting.reserve(name, car)
            elif command == 5:
                cond = True
                car='SMART BRABUS'
                Renting.reserve(name, car)
            else: 
                command = input("\nLAS OPCIONES SON LAS QUE APARECEN EN EL MENU(1, 2, 3 , 4 y 5).ELIGE UNA OPCIÓN PARA CONTINUAR: ")
                Renting.menu(name)
    
        @staticmethod
        def reserve(name, car, session_key):
            try:
                data = Renting.load_data()
                if data is not None:
                    rented_cars = 0
                    for rental in data:
                        if 'car' in rental and rental['car'] == car and rental['rented']:
                            rented_cars += 1
                    
                    if rented_cars == 10:
                        # Mensaje de error cifrado para el usuario
                        error_message = f"Lo sentimos, no quedan {car} disponibles. Pruebe con otro coche."
                        nonce, encrypted_message = Encryption.cifrar_chacha20(session_key, error_message.encode('utf-8'))
                        return nonce, encrypted_message
                    
                    # Solicitar y validar fecha y días de alquiler como antes
                    while True:
                        try:
                            rent_time_str = input('\nIntroduce una fecha de reserva en formato DD/MM/AAAA: ')
                            rent_time = datetime.strptime(rent_time_str, "%d/%m/%Y")
                            if rent_time <= datetime.now():
                                print('\nLa fecha debe de ser mayor que la actual, inténtelo de nuevo.')
                            else:
                                break
                        except ValueError:
                            print('\nFormato de fecha inválido, intentelo de nuevo.')
                    
                    while True:
                        try:
                            time = int(input('\n¿Cuántos días desea alquilar el coche?: '))
                            break
                        except ValueError:
                            print('Por favor, ingrese un número de días entero.')
                    
                    # Calcular fecha de devolución y formato
                    return_time = rent_time + timedelta(days=time)
                    frent_time = rent_time.strftime("%d/%m/%Y") + " 08:00:00"
                    freturn_time = return_time.strftime("%d/%m/%Y") + " 08:00:00"
                    
                    # Generar un número de reserva único
                    reserve_number = str(len(data) + 1).zfill(10)
                    
                    rental_data = {
                        'name': name,
                        'car': car,
                        'rent_time': frent_time,
                        'return_time': freturn_time,
                        'rented': False,
                        'reserve_number': reserve_number
                    }
                    
                    # Añadir a la base de datos y cifrar con sesión
                    data.append(rental_data)
                    Renting.save_data(data)

                    # Mensaje de confirmación cifrado
                    confirmation_message = f"Reserva realizada con éxito. Reserva del coche {car} del {frent_time} hasta el {freturn_time}. Número de reserva: {reserve_number}"
                    nonce, encrypted_confirmation = Encryption.cifrar_chacha20(session_key, confirmation_message.encode('utf-8'))
                    
                    return nonce, encrypted_confirmation
            
            except Exception as e:
                print(f'Error al procesar la reserva: {e}')

      
    @staticmethod
    def user_reservations(name):
        cond = False
        print("------------- SELECCIONE LA GESTION QUE DESEE -------------")
        print("\n1 - VER MIS RESERVAS")
        print("\n2 - CANCELAR RESERVAS")
        print("\n3 - VOLVER AL MENU")
        
        command = int(input("\nELIGE UNA OPCION PARA CONTINUAR: "))
        
        while not cond:
            Renting.loading()
            if command == 1:
                cond = True
                Renting.my_reservations(name)
            elif command == 2:
                cond = True
                Renting.cancel_reservation(name)
            elif command == 3:
                cond = True
                Renting.menu(name)
            else:
                command = input("\nLas opciones son las que aparecen en el menú(1, 2 y 3). Elige una opción para continuar: ")
    
    @staticmethod
    def my_reservations(name):
        try:
            # Cargamos la base de datos desencriptada
            data = Renting.load_data()
            print('\nMostrando sus reservas, porfavor espere.')
            Renting.loading()
            print(f"\nSus reservas, señor {name}:")
                
            # Mostramos todas las reservas del usuario
            for reserve in data:
                if 'name' in reserve and reserve['name'] == name:
                    print('\n')
                    print(f"Reserva del coche {reserve['car']}")
                    print(f"Día y hora de entrega: {reserve['rent_time']}")
                    print(f"Día y hora de devolución: {reserve['return_time']}")
                    print(f"Número de reserva: {reserve['reserve_number']}")
                
            # Volvemos a guardar la base de datos encriptada
            Renting.save_data(data)
            
            Renting.loading()
                    
            Renting.user_reservations(name)

        except Exception as e:
            print(f'No se han podido mostrar las reservas: {e}')
        
    @staticmethod
    def cancel_reservation(name):
        try:
            # Cargamos la base de datos desencriptada
            data= Renting.load_data()
            
            # Creamos una nueva lista donde meteremos todas las reservas menos la que quiera eliminar
            updated_data = []
            
            # Creamos una variable de decisión para encontrar la reserva
            rental_found = False
            reserve_number = input("\nPor favor, introduzaca el número de la reserva que quiere eliminar: ")
            Renting.loading()

            # Buscamos todas las reservas del usuario hasta encontrar la que quiere eliminar
            for reserve in data:   
                if reserve['name'] == name and reserve['reserve_number'] == reserve_number:
                    rental_found = True
                else:
                    updated_data.append(reserve)

            if rental_found:
                # Guardamos la nueva base de datos y la encriptamos
                Renting.save_data(updated_data)
                print("\nReserva cancelada correctamente.")
            else:
                print("No se encontró la reserva.")

        except Exception as e:
            raise e
    
        Renting.user_reservations(name)
    
