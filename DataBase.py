import json

class DataBase:
    def __init__(self):
        try:
            with open('BBDD.json', 'r') as data:
                self.data = json.load(data)
        except FileNotFoundError:
            self.data = []
        except json.JSONDecodeError:
            raise ValueError("El archivo de datos esta corrupto.")
    
    def create_account(self, name, password):
        try:
            #Verificamos si el nombre de usuario es unico
            for user in self.data:
                if user['name'] == name:
                    raise ValueError(f"El nombre de usuario {name} ya existe, por favor introduce otro.")
            
            print("Nombre de usuario válido.")
            
            #Verificamos longitud de la contraseña 
            if len(password) < 8:
                raise ValueError("La contraseña debe contener al menos 8 caracteres.")
            
            #Verificamos contenido de la contraseña
            mayus = any(char.isupper() for char in password)
            minus = any(char.islower() for char in password)
            num = any(char.isdigit() for char in password)
            if not(mayus and minus and num):
                raise ValueError("La contraseña debe contener al menos una mayúscula, una minúscula y un número.")
            
            print('Contraseña válida.')
            
            #Una vez verificados ambos campos (nombre y contrsaeña) añadimos el usuario en la base de datos
            new_user = {'name':name, 'password':password}
            self.data.append(new_user)
            with open('BBDD.json', 'w') as bd:
                json.dump(self.data, bd, indent='\t')
                       
        except Exception as e:
            raise e
    
    def login(self, name, password):
        for user in self.data:
            if (user['name'] == name) and (user['password'] == password):
                return True

        #Lanzamos un error si el nombre y la contraseña no se encuentran en nuestra base de datos.
        raise ValueError("El nombre y/o contraseña no son correctos.")
            
            
                    

                
            
        
                
            