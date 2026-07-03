#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
from colorama import init, Fore, Style

# Inicializar colorama para colores en consola
init(autoreset=True)

def mostrar_banner():
    """Muestra el banner de la herramienta desde un archivo."""
    try:
        with open("banners/banner.txt", "r") as f:
            banner = f.read()
        print(Fore.CYAN + banner)
    except FileNotFoundError:
        print(Fore.RED + "[!] No se encontró el archivo banners/banner.txt")
        print(Fore.YELLOW + "[*] Usando banner por defecto:")
        print(Fore.GREEN + """
  __  __            _                _    
 |  \/  |          | |              | |   
 | \  / |  ___  ___| |_ __ _  _ __ | | __
 | |\/| | / _ \/ __| __/ _` | '_ \| |/ /
 | |  | ||  __/\__ \ || (_| | | | |   < 
 |_|  |_| \___||___/\__\__,_|_| |_|_|\_\

       Mxcrack-ng - WiFi Security Tool      
============================================
""")

def mostrar_menu():
    """Muestra el menú principal con 7 opciones."""
    print(Fore.YELLOW + "\n" + "="*40)
    print(Fore.CYAN + "             MENÚ PRINCIPAL")
    print(Fore.YELLOW + "="*40)
    print(Fore.WHITE + " 1. Capturar paquetes")
    print(Fore.WHITE + " 2. Probar redes")
    print(Fore.WHITE + " 3. Ataques")
    print(Fore.WHITE + " 4. Herramientas")
    print(Fore.WHITE + " 5. Opciones")
    print(Fore.WHITE + " 6. Ayuda")
    print(Fore.RED + " 7. Salir")
    print(Fore.YELLOW + "="*40)

def opcion_capturar():
    print(Fore.GREEN + "\n[*] Función 'Capturar paquetes' seleccionada.")
    print(Fore.YELLOW + "[*] Aquí iría la lógica para capturar tráfico WiFi.")
    input(Fore.CYAN + "\nPresiona Enter para volver al menú...")

def opcion_probar():
    print(Fore.GREEN + "\n[*] Función 'Probar redes' seleccionada.")
    print(Fore.YELLOW + "[*] Aquí iría la lógica para analizar y probar redes.")
    input(Fore.CYAN + "\nPresiona Enter para volver al menú...")

def opcion_ataques():
    print(Fore.GREEN + "\n[*] Función 'Ataques' seleccionada.")
    print(Fore.YELLOW + "[*] Aquí iría la lógica para ejecutar ataques (ej. deautenticación).")
    input(Fore.CYAN + "\nPresiona Enter para volver al menú...")

def opcion_herramientas():
    print(Fore.GREEN + "\n[*] Función 'Herramientas' seleccionada.")
    print(Fore.YELLOW + "[*] Aquí irían herramientas adicionales (ej. escáner de puertos).")
    input(Fore.CYAN + "\nPresiona Enter para volver al menú...")

def opcion_opciones():
    print(Fore.GREEN + "\n[*] Función 'Opciones' seleccionada.")
    print(Fore.YELLOW + "[*] Aquí iría la configuración de la herramienta.")
    input(Fore.CYAN + "\nPresiona Enter para volver al menú...")

def opcion_ayuda():
    print(Fore.GREEN + "\n[*] Función 'Ayuda' seleccionada.")
    print(Fore.WHITE + """
    Mxcrack-ng - Guía Rápida
    =========================
    Esta herramienta simula funciones de aircrack-ng sin modo monitor.
    Las opciones son:
    1. Capturar paquetes: Para interceptar tráfico de red.
    2. Probar redes: Para analizar la seguridad de redes WiFi.
    3. Ataques: Para realizar pruebas de penetración básicas.
    4. Herramientas: Utilidades adicionales para pentesting.
    5. Opciones: Configuración de la herramienta.
    6. Ayuda: Muestra este mensaje.
    7. Salir: Cierra la aplicación.
    """)
    input(Fore.CYAN + "\nPresiona Enter para volver al menú...")

def main():
    """Bucle principal del programa."""
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')  # Limpia la pantalla
        mostrar_banner()
        mostrar_menu()
        
        try:
            opcion = input(Fore.CYAN + "\n[+] Selecciona una opción (1-7): " + Fore.WHITE)
            
            if opcion == '1':
                opcion_capturar()
            elif opcion == '2':
                opcion_probar()
            elif opcion == '3':
                opcion_ataques()
            elif opcion == '4':
                opcion_herramientas()
            elif opcion == '5':
                opcion_opciones()
            elif opcion == '6':
                opcion_ayuda()
            elif opcion == '7':
                print(Fore.RED + "\n[!] Saliendo de Mxcrack-ng... ¡Hasta luego!")
                sys.exit(0)
            else:
                print(Fore.RED + "\n[!] Opción no válida. Por favor, elige un número del 1 al 7.")
                input(Fore.CYAN + "\nPresiona Enter para continuar...")
        except KeyboardInterrupt:
            print(Fore.RED + "\n\n[!] Interrupción detectada. Saliendo...")
            sys.exit(0)

if __name__ == "__main__":
    # Verificar que se ejecute con permisos de root/administrador (opcional)
    if os.geteuid() != 0:
        print(Fore.YELLOW + "[!] No tienes permisos de root. Algunas funciones pueden no funcionar correctamente.")
    main()
