import os
import subprocess
import time

# Función para limpiar la pantalla dependiendo del sistema operativo
def limpiar_pantalla():
    if os.name == 'posix':  # Unix/Linux/MacOS
        _ = os.system('clear')
    else:  # Windows
        _ = os.system('cls')

# Función para mostrar el banner
def mostrar_banner():
    print('██████  ███████        █████  ███    ██  █████  ██      ██ ███████ ███████ ██████  ')
    print('██   ██ ██            ██   ██ ████   ██ ██   ██ ██      ██    ███  ██      ██   ██ ')
    print('██████  ███████ █████ ███████ ██ ██  ██ ███████ ██      ██   ███   █████   ██████  ')
    print('██   ██      ██       ██   ██ ██  ██ ██ ██   ██ ██      ██  ███    ██      ██   ██ ')
    print('██████  ███████       ██   ██ ██   ████ ██   ██ ███████ ██ ███████ ███████ ██   ██ ')
    print('                              Break Security-ANALIZER                              ')

# Función para mostrar el menú principal
def mostrar_menu():
    limpiar_pantalla()
    mostrar_banner()
    print("Selecciona una opción:")
    print("1. capturar Paquetes ")
    print("2. Analizar con SCAPY")
    print("3. solo por ip")
    print("4. Auditar con Pyshark")
    print("5. Generar estadistica")
    print("6. Salir")

# Función principal del programa
def main():
    while True:
        mostrar_menu()
        opcion = input("Ingrese el número de opción: ")

        if opcion == '1':
            limpiar_pantalla()
            mostrar_banner()
            print("Redirigiendo a Escáner 1...")
            subprocess.run(['python3', 'capturar.py'])  # Ejecutar el módulo destino.py
            input("Presione Enter para continuar...")
        elif opcion == '2':
            limpiar_pantalla()
            mostrar_banner()
            print("Escanear red...")
            subprocess.run(['python3', 'estado.py'])  # Ejecutar el módulo destino.py
            input("Presione Enter para continuar...")
        elif opcion == '3':
            limpiar_pantalla()
            mostrar_banner()
            print("Analizar datos...")
            subprocess.run(['python3', 'ip.py'])  # Ejecutar el módulo destino.py
            input("Presione Enter para continuar...")
        elif opcion == '4':
            limpiar_pantalla()
            mostrar_banner()
            print("Guardar datos...")
            subprocess.run(['python3', 'analizador.py'])  # Ejecutar el módulo destino.py
            input("Presione Enter para continuar...")
        elif opcion == '5':
            limpiar_pantalla()
            mostrar_banner()
            print("Guardar datos...")
            subprocess.run(['python3', 'analisis.py'])  # Ejecutar el módulo destino.py
            input("Presione Enter para continuar...")
        elif opcion == '6':
            limpiar_pantalla()
            mostrar_banner()
            print("Saliendo del programa.")
            break
        else:
            limpiar_pantalla()
            mostrar_banner()
            print("Opción no válida. Por favor, ingrese un número de opción válido.")
            input("Presione Enter para continuar...")

if __name__ == "__main__":
    main()
