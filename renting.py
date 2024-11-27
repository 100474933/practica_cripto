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
            public_key_path += '/keys_and_certificate/public_key.pem'
            
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
                private_key_path += '/keys_and_certificate/private_key.pem' 
                simetric_key_path += '/keys_and_certificate/renting_simetric_encrypted_key.bin'
                
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

        print("    ______             ______             ______                ______                     ______          ")
        print("   /|_||_\\`.__       /|_||_\\`.__       /|_||_\\`.__          /|_||_\\`.__               /|_||_\\`.__     ")
        print("  (   _    _ _ \\    (   _    _ _ \\    (   _    _ _ \\       (   _    _ _ \\            (   _    _ _ \\   ")
        print("  =`-(_)--(_)-'      =`-(_)--(_)-'      =`-(_)--(_)-'         =`-(_)--(_)-'              =`-(_)--(_)-'     ")
        print("------------------>------------------->------------------>------------------------->---------------------->")
        print(" |    AUDI X5       |  TOYOTA YARIS   |    BMW 320D       |    MITSUBISHI MONTERO   |    SMART BRABUS   |  ")

        
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
    def reserve(name, car):
        try:
            # Solicitar al servidor los datos iniciales (lista de coches alquilados)
            print("[CLIENTE] Enviando solicitud para cargar datos cifrados...")
            encrypted_request = Encryption.encrypt_message(json.dumps({"action": "load_data"}))
            
            # Simulación de descifrado en el servidor y envío de respuesta
            print("[INFO] Descifrando datos recibidos del servidor...")
            decrypted_request = json.loads(Encryption.decrypt_message(encrypted_request))
            
            # Verificar que la solicitud es válida
            if decrypted_request.get("action") != "load_data":
                raise ValueError("[ERROR] Solicitud inválida recibida en el servidor.")
            
            # Cargar datos (simulación de datos del servidor)
            data = Renting.load_data()  # Aquí deberías cargar la base de datos del servidor
            encrypted_response = Encryption.encrypt_message(json.dumps(data))
            
            # Descifrar respuesta del servidor en el cliente
            print("[INFO] Descifrando datos recibidos del servidor...")
            response_data = json.loads(Encryption.decrypt_message(encrypted_response))
            
            # Validar y cargar datos descifrados
            if not isinstance(response_data, list):
                raise ValueError("[ERROR] Los datos descifrados no tienen el formato esperado.")

            # Verificar disponibilidad del coche seleccionado
            rented_cars = sum(1 for rental in response_data if rental.get("car") == car and rental.get("rented", False))
            if rented_cars >= 10:
                print(f"[INFO] Lo sentimos, no quedan {car} disponibles. Pruebe con otro coche.")
                Renting.reserve_menu(name)
                return

            # Solicitar fecha de reserva al cliente
            while True:
                try:
                    rent_time_str = input("[CLIENTE] Introduce una fecha de reserva (DD/MM/AAAA): ")
                    print("[CLIENTE] Enviando fecha cifrada al servidor...")
                    encrypted_date = Encryption.encrypt_message(json.dumps({"rent_time": rent_time_str}))
                    
                    # Simulación de respuesta del servidor validando la fecha
                    print("[INFO] Descifrando fecha recibida del cliente...")
                    decrypted_date = json.loads(Encryption.decrypt_message(encrypted_date))
                    rent_time = datetime.strptime(decrypted_date.get("rent_time"), "%d/%m/%Y")
                    
                    if rent_time <= datetime.now():
                        print("[INFO] La fecha debe ser mayor que la actual. Inténtalo de nuevo.")
                    else:
                        break
                except ValueError:
                    print("[INFO] Formato de fecha inválido. Inténtalo de nuevo.")

            # Solicitar duración del alquiler al cliente
            while True:
                try:
                    days = int(input("[CLIENTE] ¿Cuántos días deseas alquilar el coche?: "))
                    print("[CLIENTE] Enviando duración cifrada al servidor...")
                    encrypted_days = Encryption.encrypt_message(json.dumps({"days": days}))

                    # Simulación de respuesta del servidor
                    print("[INFO] Descifrando duración recibida del cliente...")
                    decrypted_days = json.loads(Encryption.decrypt_message(encrypted_days))
                    days = int(decrypted_days.get("days"))
                    break
                except ValueError:
                    print("[INFO] Ingresa un número válido de días.")

            return_time = rent_time + timedelta(days=days)

            # Formatear las fechas
            frent_time = rent_time.strftime("%d/%m/%Y") + " 08:00:00"
            freturn_time = return_time.strftime("%d/%m/%Y") + " 08:00:00"

            reserve_number = str(len(response_data) + 1).zfill(10)
            rental_data = {
                'name': name, 
                'car': car, 
                'rent_time': frent_time, 
                'return_time': freturn_time, 
                'rented': False, 
                'reserve_number': reserve_number
            }
            
            # Añadimos el nuevo registro de alquiler a la base de datos y la encriptamos
            data.append(rental_data)
            Renting.save_data(data)
            
            print('Reserva realizada con éxito.')
            print(f"Reserva del coche {car} del día {frent_time} hasta el día {freturn_time}")
            print(f"Número de reserva: {reserve_number}")

            Renting.menu(name)
            
        except Exception as e:
            print(f'Error al realizar la reserva: {e}')


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
            print(f"\nSus reservas, señor/a {name}:")
                
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
    