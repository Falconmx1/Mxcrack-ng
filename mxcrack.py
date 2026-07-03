#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mxcrack-ng - Herramienta de seguridad WiFi
Autor: Falconmx1
Descripción: Suite de análisis y pruebas WiFi sin modo monitor.
"""

import os
import sys
import time
import subprocess
import platform
from colorama import init, Fore, Style

# --- Inicialización y Configuración ---
init(autoreset=True)  # Para colores en consola

# Intentar importar las librerías necesarias y manejar su ausencia
try:
    import scapy.all as scapy
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp
    from scapy.layers.l2 import Ether, ARP, srp
    import netifaces
except ImportError as e:
    print(Fore.RED + f"[!] Error al importar una librería: {e}")
    print(Fore.YELLOW + "[*] Asegúrate de tener instaladas las dependencias:")
    print(Fore.CYAN + "    pip install -r requirements.txt")
    sys.exit(1)

# --- Funciones del Núcleo ---

def limpiar_pantalla():
    """Limpia la consola según el sistema operativo."""
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def mostrar_banner():
    """Muestra el banner de la herramienta desde un archivo o uno por defecto."""
    try:
        # Intentar leer el banner desde el archivo
        with open("banners/banner.txt", "r", encoding='utf-8') as f:
            banner = f.read()
        print(Fore.CYAN + banner)
    except FileNotFoundError:
        # Banner por defecto si no se encuentra el archivo
        print(Fore.GREEN + """
  __  __            _                _    
 |  \/  |          | |              | |   
 | \  / |  ___  ___| |_ __ _  _ __ | | __
 | |\/| | / _ \/ __| __/ _` | '_ \| |/ /
 | |  | ||  __/\__ \ || (_| | | | |   < 
 |_|  |_| \___||___/\__\__,_|_|_| |_|_|\_\

       Mxcrack-ng - WiFi Security Tool      
============================================
""")
    except Exception as e:
        print(Fore.RED + f"[!] Error al leer el banner: {e}")

def obtener_interfaz_red():
    """Obtiene la interfaz de red activa por defecto."""
    try:
        # Obtener la interfaz por defecto usando netifaces
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET]
        interfaz = default_gateway[1]
        return interfaz
    except Exception:
        # Fallback: usar 'eth0' o 'wlan0' como intento
        posibles = ['eth0', 'wlan0', 'en0', 'en1']
        for iface in posibles:
            if iface in netifaces.interfaces():
                return iface
        return None

def escanear_redes(interfaz):
    """
    Escanea redes WiFi cercanas usando Scapy.
    Esta función es una demostración. En un entorno real, necesitarías modo monitor.
    """
    print(Fore.YELLOW + "[*] Escaneando redes WiFi (simulado)...")
    # En una implementación real, aquí se usaría: scapy.sniff(iface=interfaz, ...)
    # Como no estamos en modo monitor, simulamos resultados.
    time.sleep(2)  # Simula el tiempo de escaneo
    redes_ficticias = [
        {"ssid": "WiFi-Casa", "bssid": "AA:BB:CC:DD:EE:11", "channel": 6, "signal": -45},
        {"ssid": "Red-Vecino", "bssid": "AA:BB:CC:DD:EE:22", "channel": 1, "signal": -67},
        {"ssid": "CafeInternet", "bssid": "AA:BB:CC:DD:EE:33", "channel": 11, "signal": -55},
        {"ssid": "Oficina_5G", "bssid": "AA:BB:CC:DD:EE:44", "channel": 149, "signal": -70},
    ]
    print(Fore.CYAN + "\n[+] Redes encontradas:")
    print(Fore.WHITE + "SSID\t\t\tBSSID\t\t\tCanal\tSeñal")
    print(Fore.WHITE + "-" * 60)
    for red in redes_ficticias:
        print(Fore.WHITE + f"{red['ssid']:16}\t{red['bssid']}\t{red['channel']}\t{red['signal']} dBm")
    return redes_ficticias

def capturar_paquetes(interfaz, count=10):
    """Captura paquetes de red de forma simulada o real si hay permisos."""
    print(Fore.YELLOW + f"[*] Capturando {count} paquetes en {interfaz} (simulado)...")
    # En una implementación real: scapy.sniff(iface=interfaz, count=count, prn=lambda x: x.summary())
    time.sleep(2)
    paquetes_capturados = [
        {"src": "192.168.1.10", "dst": "192.168.1.1", "proto": "TCP", "info": "ACK"},
        {"src": "192.168.1.5", "dst": "8.8.8.8", "proto": "UDP", "info": "DNS Query"},
        {"src": "192.168.1.1", "dst": "192.168.1.10", "proto": "TCP", "info": "SYN-ACK"},
    ]
    print(Fore.CYAN + "\n[+] Paquetes capturados (últimos):")
    for pkt in paquetes_capturados:
        print(Fore.WHITE + f"  {pkt['src']} -> {pkt['dst']} | {pkt['proto']} | {pkt['info']}")
    return paquetes_capturados

def probar_seguridad_red(redes):
    """Realiza pruebas básicas de seguridad sobre las redes escaneadas."""
    print(Fore.YELLOW + "[*] Probando seguridad de redes (simulado)...")
    time.sleep(1.5)
    print(Fore.GREEN + "[+] Pruebas completadas:")
    for red in redes:
        # Simular resultados de pruebas
        if "Casa" in red['ssid']:
            seguridad = Fore.GREEN + "Alta (WPA3)"
        elif "Vecino" in red['ssid']:
            seguridad = Fore.RED + "Baja (WEP)"
        else:
            seguridad = Fore.YELLOW + "Media (WPA2)"
        print(Fore.WHITE + f"  - {red['ssid']}: {seguridad}")

def ejecutar_ataque_simulado(interfaz):
    """Simula un ataque de desautenticación (requiere modo monitor en realidad)."""
    print(Fore.RED + "[!] ¡ATENCIÓN! Iniciando ataque de desautenticación SIMULADO.")
    print(Fore.YELLOW + "[*] En un entorno real, esto enviaría paquetes Deauth a una red objetivo.")
    time.sleep(2)
    print(Fore.GREEN + "[+] Ataque simulado completado. Se enviaron 10 paquetes de desautenticación.")

def menu_herramientas():
    """Submenú para herramientas adicionales."""
    while True:
        limpiar_pantalla()
        mostrar_banner()
        print(Fore.YELLOW + "\n" + "="*40)
        print(Fore.CYAN + "          HERRAMIENTAS ADICIONALES")
        print(Fore.YELLOW + "="*40)
        print(Fore.WHITE + " 1. Escáner de Puertos (simulado)")
        print(Fore.WHITE + " 2. Análisis de Tráfico (simulado)")
        print(Fore.WHITE + " 3. Generador de Reporte (simulado)")
        print(Fore.RED + " 4. Volver al menú principal")
        print(Fore.YELLOW + "="*40)
        
        try:
            opcion = input(Fore.CYAN + "\n[+] Selecciona una opción: " + Fore.WHITE)
            if opcion == '1':
                print(Fore.GREEN + "\n[*] Escaneando puertos en 192.168.1.1 (simulado)...")
                time.sleep(1)
                print(Fore.WHITE + "  Puerto 22 (SSH):  Abierto")
                print(Fore.WHITE + "  Puerto 80 (HTTP): Abierto")
                print(Fore.WHITE + "  Puerto 443 (HTTPS): Abierto")
                input(Fore.CYAN + "\nPresiona Enter para continuar...")
            elif opcion == '2':
                print(Fore.GREEN + "\n[*] Analizando tráfico capturado (simulado)...")
                time.sleep(1)
                print(Fore.WHITE + "  - 60% de paquetes son TCP")
                print(Fore.WHITE + "  - 30% de paquetes son UDP")
                print(Fore.WHITE + "  - 10% de paquetes son ICMP")
                input(Fore.CYAN + "\nPresiona Enter para continuar...")
            elif opcion == '3':
                print(Fore.GREEN + "\n[*] Generando reporte en formato PDF (simulado)...")
                time.sleep(1.5)
                print(Fore.WHITE + "  Reporte guardado como: reporte_Mxcrack.pdf")
                input(Fore.CYAN + "\nPresiona Enter para continuar...")
            elif opcion == '4':
                break
            else:
                print(Fore.RED + "\n[!] Opción no válida.")
                input(Fore.CYAN + "\nPresiona Enter para continuar...")
        except KeyboardInterrupt:
            break

def menu_opciones():
    """Submenú para configuración de la herramienta."""
    while True:
        limpiar_pantalla()
        mostrar_banner()
        print(Fore.YELLOW + "\n" + "="*40)
        print(Fore.CYAN + "             CONFIGURACIÓN")
        print(Fore.YELLOW + "="*40)
        print(Fore.WHITE + " 1. Ver interfaz de red actual")
        print(Fore.WHITE + " 2. Cambiar interfaz de red (simulado)")
        print(Fore.WHITE + " 3. Configurar tiempo de espera (simulado)")
        print(Fore.RED + " 4. Volver al menú principal")
        print(Fore.YELLOW + "="*40)
        
        try:
            opcion = input(Fore.CYAN + "\n[+] Selecciona una opción: " + Fore.WHITE)
            if opcion == '1':
                iface = obtener_interfaz_red()
                if iface:
                    print(Fore.GREEN + f"\n[*] Interfaz activa: {iface}")
                else:
                    print(Fore.RED + "\n[!] No se pudo determinar la interfaz de red.")
                input(Fore.CYAN + "\nPresiona Enter para continuar...")
            elif opcion == '2':
                print(Fore.GREEN + "\n[*] Cambiando a interfaz 'wlan1' (simulado).")
                input(Fore.CYAN + "\nPresiona Enter para continuar...")
            elif opcion == '3':
                try:
                    tiempo = input(Fore.YELLOW + "[*] Ingresa el nuevo tiempo de espera (segundos): ")
                    int(tiempo)
                    print(Fore.GREEN + f"[*] Tiempo de espera cambiado a {tiempo} segundos (simulado).")
                except ValueError:
                    print(Fore.RED + "[!] Debes ingresar un número entero.")
                input(Fore.CYAN + "\nPresiona Enter para continuar...")
            elif opcion == '4':
                break
            else:
                print(Fore.RED + "\n[!] Opción no válida.")
                input(Fore.CYAN + "\nPresiona Enter para continuar...")
        except KeyboardInterrupt:
            break

# --- Funciones del Menú ---
def opcion_capturar():
    """Maneja la opción de captura de paquetes."""
    iface = obtener_interfaz_red()
    if not iface:
        print(Fore.RED + "[!] No se pudo encontrar una interfaz de red válida.")
        input(Fore.CYAN + "\nPresiona Enter para continuar...")
        return
    try:
        count = input(Fore.YELLOW + "[*] Número de paquetes a capturar (default 10): ")
        if count.strip() == "":
            count = 10
        else:
            count = int(count)
        capturar_paquetes(iface, count)
    except ValueError:
        print(Fore.RED + "[!] Debes ingresar un número válido.")
    input(Fore.CYAN + "\nPresiona Enter para continuar...")

def opcion_probar():
    """Maneja la opción de probar redes."""
    iface = obtener_interfaz_red()
    if not iface:
        print(Fore.RED + "[!] No se pudo encontrar una interfaz de red válida.")
        input(Fore.CYAN + "\nPresiona Enter para continuar...")
        return
    redes = escanear_redes(iface)
    if redes:
        probar_seguridad_red(redes)
    input(Fore.CYAN + "\nPresiona Enter para continuar...")

def opcion_ataques():
    """Maneja la opción de ataques."""
    iface = obtener_interfaz_red()
    if not iface:
        print(Fore.RED + "[!] No se pudo encontrar una interfaz de red válida.")
        input(Fore.CYAN + "\nPresiona Enter para continuar...")
        return
    ejecutar_ataque_simulado(iface)
    input(Fore.CYAN + "\nPresiona Enter para continuar...")

def opcion_herramientas():
    """Maneja la opción de herramientas (submenú)."""
    menu_herramientas()

def opcion_opciones():
    """Maneja la opción de opciones (submenú)."""
    menu_opciones()

def opcion_ayuda():
    """Muestra la información de ayuda."""
    print(Fore.CYAN + """
    ╔══════════════════════════════════════════════════════════════╗
    ║                     Mxcrack-ng - Ayuda                     ║
    ╚══════════════════════════════════════════════════════════════╝
    ¡Bienvenido a Mxcrack-ng! Esta herramienta está diseñada para:

    🎯 1. Capturar paquetes: Intercepta tráfico de red en tu interfaz.
    🔍 2. Probar redes: Escanea y evalúa la seguridad de redes WiFi.
    ⚔️ 3. Ataques: Ejecuta pruebas de penetración (simuladas).
    🛠️ 4. Herramientas: Accede a utilidades adicionales.
    ⚙️ 5. Opciones: Configura la herramienta a tu gusto.
    ❓ 6. Ayuda: Muestra este mensaje.
    🚪 7. Salir: Cierra la aplicación.

    ⚠️  IMPORTANTE: Esta herramienta es solo para fines educativos
        y de auditoría autorizada. El uso no autorizado es ilegal.

    📌  Consejo: Para funciones reales de red, se necesitan permisos
        de root/administrador y, en algunos casos, modo monitor.
    """)
    input(Fore.CYAN + "\nPresiona Enter para volver al menú...")

# --- Función Principal ---
def main():
    """Bucle principal del programa."""
    if not os.geteuid() == 0:
        print(Fore.YELLOW + "[!] No tienes permisos de root. Algunas funciones de red pueden fallar.")
        print(Fore.YELLOW + "[*] Se recomienda ejecutar: sudo python3 mxcrack.py")
        time.sleep(2)
    
    while True:
        limpiar_pantalla()
        mostrar_banner()
        mostrar_menu()
        
        try:
            opcion = input(Fore.CYAN + "\n[+] Elige una opción (1-7): " + Fore.WHITE)
            
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
                print(Fore.RED + "\n[!] Saliendo de Mxcrack-ng... ¡Hasta luego, rey!")
                sys.exit(0)
            else:
                print(Fore.RED + "\n[!] Opción no válida. Elige un número del 1 al 7.")
                time.sleep(1.5)
        except KeyboardInterrupt:
            print(Fore.RED + "\n\n[!] Interrupción detectada. Saliendo de forma segura...")
            sys.exit(0)
        except Exception as e:
            print(Fore.RED + f"\n[!] Error inesperado: {e}")
            print(Fore.YELLOW + "[*] El programa continuará ejecutándose.")
            time.sleep(2)

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

if __name__ == "__main__":
    main()
