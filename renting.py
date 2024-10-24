import json
import os
from datetime import date, datetime, timedelta
from users import DataBase
from encryptation import Encryption
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend




class Renting:
    db = DataBase()
    
    @staticmethod
    def loading():
        print("-"*150)
        
    @staticmethod
    def load_data(data):
        try:
            with open('BBDD_renting.json', 'w') as bd:
                json.dump(data, bd, indent = '\t')
        except json.JSONDecodeError:
            print("El archivo de datos está corrupto.")
        except Exception as e:
            print(f"Error al escribir en el archivo: {e}")
    
    @staticmethod   
    def open_data():
        if os.path.exists('BBDD_renting.json'):
            try:
                with open('BBDD_renting.json', 'r') as data:
                    content = data.read().strip()  # Leemos el archivo y eliminamos espacios en blanco
                    if content:  # Solo intentamos cargar el JSON si hay contenido
                        renting_data = json.loads(content)
                    else:
                        renting_data = []  # Si el archivo está vacío, iniciamos con lista vacía
            except json.JSONDecodeError:
                print("EL ARCHIVO DE DATOS ES CORRUPTO. INICIANDO UNA BASE DE DATOS VACIA.")
                renting_data = []  # Iniciar base de datos vacía si el archivo está corrupto
            except Exception as e:
                print(f"ERROR AL LEER EL ARCHIVO: {e}")
                renting_data = []  # Si ocurre algún otro error, iniciar lista vacía
        else:
        # Si el archivo no existe, crearlo con una base de datos vacía
            renting_data = []
            Renting.load_data(renting_data)  # Guardar la base de datos vacía

        return renting_data
    
    @staticmethod
    def time_out():
        data = Renting.open_data()
        actual_date = datetime.now()
        for car in data:
            if 'return_time' in car:
                return_date = car['return_time']
                return_date_obj = datetime.strptime(return_date, "%d/%m/%Y %H:%M:%S")
                if return_date_obj <= actual_date:
                    car['rented'] = False
        
        Renting.load_data(data)
    
    @staticmethod
    def menu(name):
        #Cada vez que iniciamos sesion se actualiza el estado de renting de los coches
        Renting.time_out()
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
    def reserve(name, car):
        data = Renting.open_data()
        #Comprobamos que el fichero data no este vacio
        if data != None:    
            #Comprobamos que queden coches en el garage
            rented_cars = 0
            for rental in data:
                if 'car' in rental and rental['car'] == car and rental['rented'] == True:
                    rented_cars += 1
            
            if rented_cars == 10:
                print(f"LO SENTIMOS, NO QUEDAN {car} DISPONIBLES. PRUEBE CON OTRO COCHE.")
                Renting.loading()
                Renting.reserve(name, car)
            #Si quedan coches añadimos la reserva a la base de datos
            else:
                #Solicitamos la fecha de reserva y validamos que es el formato correcto
                while True:
                    try: 
                        rent_time_str = input('\nINTRODUCE UNA FECHA DE RESERVA EN FORMATO DD/MM/AAAA: ')
                        rent_time = datetime.strptime(rent_time_str, "%d/%m/%Y")
                        break 
                    except ValueError:
                        print('\nFORMATO DE FECHA INVALIDO, INTENTELO DE NUEVO')
                
                #Solicitamos el numero de dias de alquiler y verificamos que sea un numero entero
                while True:
                    try:      
                        time = int(input('\n¿CUÁNTOS DÍAS DESEA ALQUILAR EL COCHE?: '))
                        break
                    except ValueError:
                        print('POR FAVOR, INGRESE UN NUMERO DE DIAS ENTERO')
                
                #Calculamos la fecha de devolución del coche
                return_time = rent_time + timedelta(days=time)
                
                #Formateamos las fechas para que sean strings
                frent_time = rent_time.strftime("%d/%m/%Y")
                frent_time += " 08:00:00"
                freturn_time = return_time.strftime("%d/%m/%Y")
                freturn_time += " 08:00:00"
                Renting.loading()
                print('PROCESANDO SU RESERVA.')
                #Antes de procesar la reserva creamos un numero de reserva único
                reserve_number = str(len(data) + 1).zfill(10)
                
                rental_data = {
                    'name': name, 
                    'car': car, 
                    'rent_time': frent_time, 
                    'return_time': freturn_time, 
                    'rented': True, 
                    'reserve_number': reserve_number}
                
                # Generamos un par de claves RSA
                private_key, public_key = Encryption.generar_claves_rsa()

                
                # Ciframos los datos de la reserva
                encrypted_rental_data = Encryption.cifrar_clave_rsa(public_key, json.dumps(rental_data).encode())


                # Creamos el nuevo registro de alquiler con solo los datos cifrados
                new_rental = {
                    'encrypted_data': base64.urlsafe_b64encode(encrypted_rental_data).decode(),
                    'login': False
                }
                
                # Añadimos el nuevo registro de alquiler a la base de datos (lista en memoria)
                data.append(new_rental)
                with open('BBDD_rentals.json', 'w') as bd:
                    json.dump(data, bd, indent='\t')

                # Guardamos la clave privada en un archivo separado
                with open(f'{name}_rental_private_key.pem', 'wb') as key_file:
                    key_file.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                
                print('RESERVA REALIZADA CON EXITO.')
                print(f"RESERVA DEL COCHE {car} DEL DIA {frent_time} HASTA EL DIA {freturn_time}")
                print(f"numero de reserva: {reserve_number}")

            
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
                command = input("\nLAS OPCIONES SON LAS QUE APARECEN EN EL MENU(1, 2 y 3).ELIGE UNA OPCIÓN PARA CONTINUAR: ")

    
    
    @staticmethod
    def my_reservations(name):
        data= Renting.open_data()
        try:
            for rental in data:
                encrypted_data = rental['encrypted_data'].encode()
                
                # Cargamos la clave privada RSA desde el archivo
                with open(f'{name}_rental_private_key.pem', 'rb') as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,
                        backend=default_backend()
                    )
                
                # Cargamos la clave simétrica cifrada desde el archivo
                with open(f'{name}_rental_encrypted_key.bin', 'rb') as key_file:
                    encrypted_key = key_file.read()
                
                # Desciframos la clave simétrica utilizando la clave privada RSA
                key = Encryption.descifrar_clave_rsa(private_key, encrypted_key)
                
                # Desciframos los datos de la reserva utilizando la clave simétrica
                decrypted_rental_data = Encryption.descifrar_datos(encrypted_data, key)
                rental_data = json.loads(decrypted_rental_data)
                
                if rental_data['name'] == name:
                    print (rental_data)
                else:
                    print("No se encontraron reservas.")
                
                Renting.user_reservations(name)

        except Exception as e:
            raise e
        
    
    def cancel_reservation(name):
        data= Renting.open_data()
        try:
            updated_data = []
            rental_found = False
            reserve_number = input("POR FAVOR, INTRODUZCA EL NUMERO DE LA RESERVA QUE DESEA ELIMINAR: ")

            for rental in data:
                encrypted_data = rental['encrypted_data'].encode()
                
                # Cargamos la clave privada RSA desde el archivo
                with open(f'{name}_rental_private_key.pem', 'rb') as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read(),
                        password=None,
                        backend=default_backend()
                    )
                
                # Cargamos la clave simétrica cifrada desde el archivo
                with open(f'{name}_rental_encrypted_key.bin', 'rb') as key_file:
                    encrypted_key = key_file.read()
                
                # Desciframos la clave simétrica utilizando la clave privada RSA
                key = Encryption.descifrar_clave_rsa(private_key, encrypted_key)
                
                # Desciframos los datos de la reserva utilizando la clave simétrica
                decrypted_rental_data = Encryption.descifrar_datos(encrypted_data, key)
                rental_data = json.loads(decrypted_rental_data)
                
                if rental_data['name'] == name and rental_data['reserve_number'] == reserve_number:
                    rental_found = True
                else:
                    updated_data.append(rental)

            if rental_found:
                with open('BBDD_rentals.json', 'w') as bd:
                    json.dump(updated_data, bd, indent='\t')
                print("Reserva cancelada correctamente.")
            else:
                print("No se encontró la reserva.")
            Renting.user_reservations(name)

        except Exception as e:
            raise e
    