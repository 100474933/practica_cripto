import json
from DataBase import DataBase

class Renting:
    
    @staticmethod
    def menu():
        cond = True
        
        print("  _____   ____   ____  __ __  /\ ")
        print(" /     \_/ __ \ /    \|  |  \ \/ ")
        print("|  Y Y  \  ___/|   |  \  |  / /\ ")
        print("|__|_|  /\___  >___|  /____/  \/ ")
        print("      \/     \/     \/           ")
        
        print("\n1 - RESERVAR COCHES")
        print("\n2 - MIS RESERVAS")
        print("\n3 - CERRAR SESIÓN")
        
        command = input("\nELIGE UNA OPCIÓN PARA CONTINUAR")
        
        while cond:
            if command == 1:
                cond = True
                Renting.reserve()
            elif command == 2:
                cond = True
                Renting.user_reservations()
            elif command == 3:
                cond = True
                Renting.logout()
            else: 
                command = input("\nLAS OPCIONES SON LAS QUE APARECEN EN EL MENU(1, 2 Y 3).ELIGE UNA OPCIÓN PARA CONTINUAR")
    
    