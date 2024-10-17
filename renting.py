import json
import os
from datetime import date, datetime, timedelta
from users import DataBase

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
        actual_date = date.today()
        for car in data:
            if car['freturn_date'] >= actual_date:
                car['rented'] = False
    
    @staticmethod
    def menu(name):
        cond = False
        
        print("  _____   ____   ____  __ __  /\ ")
        print(" /     \_/ __ \ /    \|  |  \ \/ ")
        print("|  Y Y  \  ___/|   |  \  |  / /\ ")
        print("|__|_|  /\___  >___|  /____/  \/ ")
        print("      \/     \/     \/           ")
        
        print("\n1 - RESERVAR COCHES")
        print("\n2 - MIS RESERVAS")
        print("\n3 - CERRAR SESIÓN")
        
        command = int(input("\nELIGE UNA OPCIÓN PARA CONTINUAR: "))
        
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
                Renting.reserve(name, 'AUDI X5')
            elif command == 2:
                cond = True
                Renting.reserve(name, 'TOYOTA YARIS')
            elif command == 3:
                cond = True
                Renting.reserve(name, 'BMW 320D')
            elif command == 4:
                cond = True
                Renting.reserve(name, 'MITSUBISHI MONTERO')
            elif command == 5:
                cond = True
                Renting.reserve(name, 'SMART BRABUS')
            else: 
                command = input("\nLAS OPCIONES SON LAS QUE APARECEN EN EL MENU(1, 2, 3  y 4).ELIGE UNA OPCIÓN PARA CONTINUAR: ")
    
    @staticmethod
    def reserve(name, car):
        data = Renting.open_data()
        #Comprobamos que el fichero data no este vacio
        if data != None:    
            #Comprobamos que queden coches en el garage
            rented_cars = 0
            for car in data:
                if car['car'] == car and car['rented'] == True:
                    rented_cars += 1
            
            if rented_cars == 10:
                print(f"LO SENTIMOS, NO QUEDAN {car} DISPONIBLES. PRUEBE CON OTRO COCHE.")
                Renting.loading()
                Renting.reserve(name)
            #Si quedan coches añadimos la reserva a la base de datos
            else:
                #Solicitamos la fecha de reserva y validamos que es el formato correcto
                while True:
                    try: 
                        rent_date_str = input('\nINTRODUCE UNA FECHA DE RESERVA EN FORMATO DD/MM/AAAA: ')
                        rent_date = datetime.strptime(rent_date_str, "%d/%m/%Y")
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
                return_date = rent_date + timedelta(days=time)
                
                #Formateamos las fechas para que sean strings
                frent_date = rent_date.strftime("%d/%m/%Y")
                freturn_date = return_date.strftime("%d/%m/%Y")
                Renting.loading()
                print('PROCESANDO SU RESERVA.')
                #Antes de procesar la reserva creamos un numero de reserva único
                reserve_number = str(len(data) + 1).zfill(10)
                new_data = {
                    'name': name, 
                    'car': car, 
                    'rent_time': frent_date, 
                    'return_time': freturn_date, 
                    'rented': True, 
                    'reserve_number': reserve_number}
                data.append(new_data)
                Renting.load_data(data)
                Renting.loading()
                print(f"RESERVA REALIZADA CON ÉXITO. SU NUMERO DE RESERVA ES {reserve_number}")
                Renting.menu(name)

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
        data = Renting.open_data()
        if data != None:
            print('MOSTRANDO SUS RESERVAS')
            cont = 1
            Renting.loading()
            for user in data:
                if user['name'] == name and user['rented'] == True:
                    print(f"RESERVA {cont}:")
                    print(f"RESERVA DEL COCHE {user['car']} DEL DIA {user['rent_time']} HASTA EL DIA {user['return_time']}")
                    print('\n')
                    cont += 1
            
            if cont == 1:
                print('NO HAY RESERVAS QUE MOSTRAR')
        else:
            print('NO HAY RESERVAS QUE MOSTRAR')
        
        Renting.user_reservations(name)
    
    @staticmethod
    def cancel_reservation(name):
        data = Renting.open_data()
        
        if data is not None:
            command = input("POR FAVOR, INTRODUZCA EL NUMERO DE LA RESERVA QUE DESEA ELIMINAR: ")
            Renting.loading()
            cond = False
            
            # Comprobamos que la reserva existe y eliminamos si es correcto
            updated_data = []
            for reserve in data:
                if (reserve['name'] == name) and (reserve['rented'] == True) and (reserve['reserve_number'] == command):
                    cond = True
                    print('RESERVA ELIMINADA CORRECTAMENTE')
                else:
                    updated_data.append(reserve)  # Añadir solo las reservas que no se eliminaron

            # Guardamos los cambios si eliminamos alguna reserva
            if cond:
                Renting.load_data(updated_data)
                Renting.loading()
                Renting.menu(name)
            else:
                # Si la reserva no existe le damos la oportunidad de intentarlo de nuevo o de salir
                print('NUMERO DE RESERVA INCORRECTO. POR FAVOR COMPRUEBE SUS RESERVAS')
                command = input('SI DESEA INTENTARLO DE NUEVO PULSE 1, SI DESEA SALIR PULSE CUALQUIER TECLA')
                if command == '1':
                    Renting.cancel_reservation(name)
                else:
                    Renting.user_reservations(name)
        else:
            print('NO HAY RESERVAS QUE ELIMINAR')
            Renting.user_reservations(name)


        
        
        
        
                
                
        