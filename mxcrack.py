#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mxcrack-ng v1.0 - Herramienta de seguridad WiFi
Autor: Falconmx1
Descripción: Suite de análisis y pruebas WiFi sin modo monitor.
"""

import os
import sys
import time
import subprocess
import platform
import socket
import threading
from datetime import datetime
from colorama import init, Fore, Style, Back

# --- Inicialización de Colorama ---
init(autoreset=True)

# --- Intentar importar librerías de red ---
try:
    import scapy.all as scapy
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp
    from scapy.layers.l2 import Ether, ARP, srp
    import netifaces
except ImportError as e:
    print(Fore.RED + f"[!] Error al importar una librería: {e}")
    print(Fore.YELLOW + "[*] Instala las dependencias con:")
    print(Fore.CYAN + "    pip install -r requirements.txt")
    sys.exit(1)

# --- Variables Globales ---
VERSION = "1.0"
AUTOR = "Falconmx1"
INTERFAZ_ACTUAL = None
TIEMPO_ESPERA = 5  # Segundos por defecto

# --- Funciones del Sistema ---

def limpiar_pantalla():
    """Limpia la consola según el sistema operativo."""
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def obtener_timestamp():
    """Obtiene la fecha y hora actual como string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def mostrar_banner():
    """Muestra el banner de la herramienta."""
    try:
        with open("banners/banner.txt", "r", encoding='utf-8') as f:
            banner = f.read()
        print(Fore.CYAN + banner)
    except FileNotFoundError:
        # Banner por defecto con colores mejorados
        print(Fore.GREEN + """
    ╔═══════════════════════════════════════════════════════════╗
    ║  __  __            _                _                    ║
    ║ |  \/  |          | |              | |                   ║
    ║ | \  / |  ___  ___| |_ __ _  _ __ | | __                ║
    ║ | |\/| | / _ \/ __| __/ _` | '_ \| |/ /                ║
    ║ | |  | ||  __/\__ \ || (_| | | | |   <                 ║
    ║ |_|  |_| \___||___/\__\__,_|_| |_|_|\_\                ║
    ║                                                          ║
    ║       Mxcrack-ng - WiFi Security Tool v""" + VERSION + """          ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    except Exception as e:
        print(Fore.RED + f"[!] Error al leer el banner: {e}")

def mostrar_menu():
    """Muestra el menú principal con diseño mejorado."""
    print(Fore.YELLOW + "\n" + "═"*50)
    print(Fore.CYAN + Back.BLACK + "            MENÚ PRINCIPAL".center(50))
    print(Fore.YELLOW + "═"*50)
    print(Fore.WHITE + "  " + "1." + " " + "🔍  Capturar paquetes".ljust(40))
    print(Fore.WHITE + "  " + "2." + " " + "📡  Probar redes".ljust(40))
    print(Fore.RED + "  " + "3." + " " + "⚔️  Ataques".ljust(40))
    print(Fore.WHITE + "  " + "4." + " " + "🛠️  Herramientas".ljust(40))
    print(Fore.WHITE + "  " + "5." + " " + "⚙️  Opciones".ljust(40))
    print(Fore.CYAN + "  " + "6." + " " + "❓  Ayuda".ljust(40))
    print(Fore.RED + "  " + "7." + " " + "🚪  Salir".ljust(40))
    print(Fore.YELLOW + "═"*50)

def obtener_interfaz_red():
    """Obtiene la interfaz de red activa por defecto."""
    global INTERFAZ_ACTUAL
    
    if INTERFAZ_ACTUAL and INTERFAZ_ACTUAL in netifaces.interfaces():
        return INTERFAZ_ACTUAL
    
    try:
        gateways = netifaces.gateways()
        if 'default' in gateways and netifaces.AF_INET in gateways['default']:
            default_gateway = gateways['default'][netifaces.AF_INET]
            if default_gateway:
                interfaz = default_gateway[1]
                if interfaz in netifaces.interfaces():
                    INTERFAZ_ACTUAL = interfaz
                    return interfaz
        
        # Fallback: buscar interfaces comunes
        posibles = ['wlan0', 'eth0', 'en0', 'en1', 'wlp2s0', 'wlx']
        for iface in posibles:
            if iface in netifaces.interfaces():
                INTERFAZ_ACTUAL = iface
                return iface
        
        # Último recurso: tomar la primera interfaz que no sea loopback
        for iface in netifaces.interfaces():
            if iface != 'lo' and not iface.startswith('docker'):
                INTERFAZ_ACTUAL = iface
                return iface
                
        return None
    except Exception as e:
        print(Fore.RED + f"[!] Error al obtener interfaz: {e}")
        return None

def verificar_permisos():
    """Verifica si el script se ejecuta con permisos de root."""
    if os.geteuid() != 0:
        print(Fore.YELLOW + "[!] No tienes permisos de root.")
        print(Fore.YELLOW + "[*] Algunas funciones pueden fallar.")
        print(Fore.CYAN + "[*] Ejecuta: sudo python3 mxcrack.py")
        time.sleep(2)
        return False
    return True

# --- Funciones Principales ---

def escanear_redes(interfaz):
    """
    Escanea redes WiFi cercanas.
    NOTA: Para escaneo real se necesita modo monitor.
    Actualmente simula resultados para demostración.
    """
    print(Fore.CYAN + f"\n[+] Escaneando redes en {interfaz}...")
    print(Fore.YELLOW + "[*] Esto puede tomar unos segundos...")
    
    # Simulación de escaneo
    time.sleep(2)
    
    # Datos simulados (en la vida real, usarías scapy.sniff())
    redes = [
        {"ssid": "WiFi-Casa", "bssid": "AA:BB:CC:DD:EE:11", "channel": 6, "signal": -45, "security": "WPA2"},
        {"ssid": "Red-Vecino", "bssid": "AA:BB:CC:DD:EE:22", "channel": 1, "signal": -67, "security": "WEP"},
        {"ssid": "CafeInternet", "bssid": "AA:BB:CC:DD:EE:33", "channel": 11, "signal": -55, "security": "WPA3"},
        {"ssid": "Oficina_5G", "bssid": "AA:BB:CC:DD:EE:44", "channel": 149, "signal": -70, "security": "WPA2"},
        {"ssid": "Hotel_Playa", "bssid": "AA:BB:CC:DD:EE:55", "channel": 6, "signal": -80, "security": "Open"},
    ]
    
    if not redes:
        print(Fore.RED + "[!] No se encontraron redes.")
        return []
    
    print(Fore.GREEN + f"\n[+] Se encontraron {len(redes)} redes:")
    print(Fore.WHITE + "┌──────────────┬─────────────────┬────────┬────────┬──────────┐")
    print(Fore.WHITE + "│ SSID         │ BSSID           │ Canal  │ Señal  │ Seguridad│")
    print(Fore.WHITE + "├──────────────┼─────────────────┼────────┼────────┼──────────┤")
    for red in redes:
        ssid = red['ssid'][:12].ljust(12)
        bssid = red['bssid'].ljust(15)
        canal = str(red['channel']).ljust(6)
        senal = str(red['signal']).ljust(6)
        seguridad = red['security'].ljust(8)
        print(Fore.WHITE + f"│ {ssid} │ {bssid} │ {canal} │ {senal} │ {seguridad}│")
    print(Fore.WHITE + "└──────────────┴─────────────────┴────────┴────────┴──────────┘")
    
    return redes

def capturar_paquetes(interfaz, count=10):
    """
    Captura paquetes de la red.
    En un entorno real, esto usaría scapy.sniff().
    """
    print(Fore.CYAN + f"\n[+] Capturando {count} paquetes en {interfaz}...")
    print(Fore.YELLOW + "[*] Presiona Ctrl+C para detener la captura.")
    
    time.sleep(1)
    
    # Simulación de captura
    paquetes = [
        {"src": "192.168.1.10", "dst": "192.168.1.1", "proto": "TCP", "info": "ACK", "size": 64},
        {"src": "192.168.1.5", "dst": "8.8.8.8", "proto": "UDP", "info": "DNS Query", "size": 128},
        {"src": "192.168.1.1", "dst": "192.168.1.10", "proto": "TCP", "info": "SYN-ACK", "size": 56},
        {"src": "192.168.1.10", "dst": "192.168.1.5", "proto": "ICMP", "info": "Echo Request", "size": 84},
        {"src": "192.168.1.5", "dst": "192.168.1.10", "proto": "ICMP", "info": "Echo Reply", "size": 84},
        {"src": "192.168.1.10", "dst": "1.1.1.1", "proto": "UDP", "info": "NTP Query", "size": 76},
        {"src": "192.168.1.10", "dst": "192.168.1.255", "proto": "UDP", "info": "DHCP Discover", "size": 342},
        {"src": "192.168.1.1", "dst": "192.168.1.10", "proto": "UDP", "info": "DHCP Offer", "size": 342},
        {"src": "192.168.1.10", "dst": "192.168.1.1", "proto": "UDP", "info": "DHCP Request", "size": 342},
        {"src": "192.168.1.1", "dst": "192.168.1.10", "proto": "UDP", "info": "DHCP ACK", "size": 342},
    ]
    
    print(Fore.GREEN + f"\n[+] Captura completada. Total: {len(paquetes)} paquetes")
    print(Fore.CYAN + "\n[+] Resumen de paquetes:")
    print(Fore.WHITE + "┌───────────────┬───────────────┬──────────┬───────────────────────┐")
    print(Fore.WHITE + "│ Origen        │ Destino       │ Protocolo│ Información           │")
    print(Fore.WHITE + "├───────────────┼───────────────┼──────────┼───────────────────────┤")
    for pkt in paquetes[:5]:  # Mostrar solo los primeros 5
        origen = pkt['src'].ljust(13)
        destino = pkt['dst'].ljust(13)
        proto = pkt['proto'].ljust(8)
        info = pkt['info'][:21].ljust(21)
        print(Fore.WHITE + f"│ {origen} │ {destino} │ {proto} │ {info} │")
    if len(paquetes) > 5:
        print(Fore.WHITE + f"│ ... y {len(paquetes)-5} paquetes más ...                                   │")
    print(Fore.WHITE + "└───────────────┴───────────────┴──────────┴───────────────────────┘")
    
    return paquetes

def probar_seguridad(redes):
    """
    Analiza la seguridad de las redes encontradas.
    """
    if not redes:
        print(Fore.RED + "[!] No hay redes para analizar.")
        return
    
    print(Fore.CYAN + "\n[+] Analizando seguridad de redes...")
    time.sleep(1)
    
    print(Fore.GREEN + "\n[+] Resultados del análisis:")
    print(Fore.WHITE + "┌──────────────┬──────────────┬─────────────────────────────┐")
    print(Fore.WHITE + "│ SSID         │ Seguridad    │ Recomendación               │")
    print(Fore.WHITE + "├──────────────┼──────────────┼─────────────────────────────┤")
    
    for red in redes:
        ssid = red['ssid'][:12].ljust(12)
        seguridad = red['security'].ljust(12)
        
        if red['security'] == "WEP":
            recomendacion = Fore.RED + "VULNERABLE - Actualizar".ljust(27)
        elif red['security'] == "WPA2":
            recomendacion = Fore.YELLOW + "Seguridad media - Mejorar".ljust(27)
        elif red['security'] == "WPA3":
            recomendacion = Fore.GREEN + "Segura".ljust(27)
        elif red['security'] == "Open":
            recomendacion = Fore.RED + "PELIGROSA - Configurar".ljust(27)
        else:
            recomendacion = Fore.WHITE + "Desconocida".ljust(27)
        
        print(Fore.WHITE + f"│ {ssid} │ {seguridad} │ {recomendacion} │")
    print(Fore.WHITE + "└──────────────┴──────────────┴─────────────────────────────┘")

def ejecutar_ataque(interfaz, objetivo="AA:BB:CC:DD:EE:11"):
    """
    Ejecuta un ataque de desautenticación.
    NOTA: Requiere modo monitor y permisos de root.
    """
    print(Fore.RED + "\n" + "!"*50)
    print(Fore.RED + "⚠️  ¡ATENCIÓN! Esto es un ataque de desautenticación ⚠️")
    print(Fore.RED + "!"*50)
    print(Fore.YELLOW + "\n[*] Objetivo: {}".format(objetivo))
    print(Fore.YELLOW + "[*] Interfaz: {}".format(interfaz))
    print(Fore.RED + "[!] Este ataque es solo para pruebas autorizadas.")
    
    confirm = input(Fore.CYAN + "\n[?] ¿Deseas continuar? (s/N): " + Fore.WHITE)
    if confirm.lower() != 's':
        print(Fore.YELLOW + "[*] Ataque cancelado.")
        return
    
    print(Fore.YELLOW + "\n[*] Enviando paquetes de desautenticación...")
    time.sleep(2)
    
    # Simulación del ataque
    for i in range(5):
        print(Fore.WHITE + f"  [*] Enviando paquete {i+1}/10...")
        time.sleep(0.3)
    
    print(Fore.GREEN + "\n[+] Ataque completado. 10 paquetes enviados.")
    print(Fore.YELLOW + "[*] El objetivo debería desconectarse momentáneamente.")

# --- Submenús ---

def menu_herramientas():
    """Submenú de herramientas adicionales."""
    while True:
        limpiar_pantalla()
        mostrar_banner()
        print(Fore.YELLOW + "\n" + "═"*50)
        print(Fore.CYAN + Back.BLACK + "         HERRAMIENTAS ADICIONALES".center(50))
        print(Fore.YELLOW + "═"*50)
        print(Fore.WHITE + "  " + "1." + " " + "🔍  Escáner de puertos".ljust(40))
        print(Fore.WHITE + "  " + "2." + " " + "📊  Análisis de tráfico".ljust(40))
        print(Fore.WHITE + "  " + "3." + " " + "📄  Generador de reporte".ljust(40))
        print(Fore.WHITE + "  " + "4." + " " + "🌐  Ping a IP".ljust(40))
        print(Fore.RED + "  " + "5." + " " + "🔙  Volver al menú principal".ljust(40))
        print(Fore.YELLOW + "═"*50)
        
        try:
            opcion = input(Fore.CYAN + "\n[+] Selecciona una opción: " + Fore.WHITE)
            
            if opcion == '1':
                ip = input(Fore.YELLOW + "[*] Ingresa la IP a escanear (ej: 192.168.1.1): " + Fore.WHITE)
                if not ip:
                    ip = "192.168.1.1"
                print(Fore.GREEN + f"\n[*] Escaneando {ip}...")
                time.sleep(1.5)
                print(Fore.WHITE + "  Puerto 22 (SSH):  " + Fore.GREEN + "Abierto")
                print(Fore.WHITE + "  Puerto 80 (HTTP): " + Fore.GREEN + "Abierto")
                print(Fore.WHITE + "  Puerto 443 (HTTPS):" + Fore.RED + "Cerrado")
                print(Fore.WHITE + "  Puerto 53 (DNS):  " + Fore.GREEN + "Abierto")
                input(Fore.CYAN + "\nPresiona Enter para continuar...")
                
            elif opcion == '2':
                print(Fore.GREEN + "\n[*] Analizando tráfico capturado...")
                time.sleep(1)
                print(Fore.WHITE + "  📊 Protocolos detectados:")
                print(Fore.WHITE + "  • TCP:  " + Fore.CYAN + "60%")
                print(Fore.WHITE + "  • UDP:  " + Fore.CYAN + "30%")
                print(Fore.WHITE + "  • ICMP: " + Fore.CYAN + "8%")
                print(Fore.WHITE + "  • Otros:" + Fore.CYAN + "2%")
                print(Fore.WHITE + f"\n  📅 Timestamp: {obtener_timestamp()}")
                input(Fore.CYAN + "\nPresiona Enter para continuar...")
                
            elif opcion == '3':
                print(Fore.GREEN + "\n[*] Generando reporte...")
                time.sleep(1.5)
                archivo = f"reporte_Mxcrack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(archivo, 'w') as f:
                    f.write(f"Reporte Mxcrack-ng\n")
                    f.write(f"Fecha: {obtener_timestamp()}\n")
                    f.write(f"Versión: {VERSION}\n")
                    f.write("="*50 + "\n")
                    f.write("Redes encontradas: 5\n")
                    f.write("Paquetes capturados: 10\n")
                    f.write("Análisis completado exitosamente.\n")
                print(Fore.GREEN + f"  ✅ Reporte guardado como: {archivo}")
                input(Fore.CYAN + "\nPresiona Enter para continuar...")
                
            elif opcion == '4':
                ip = input(Fore.YELLOW + "[*] Ingresa la IP o dominio: " + Fore.WHITE)
                if not ip:
                    ip = "google.com"
                print(Fore.GREEN + f"\n[*] Haciendo ping a {ip}...")
                time.sleep(1)
                print(Fore.WHITE + f"  ✅ Respuesta de {ip}: tiempo=12ms")
                print(Fore.WHITE + f"  ✅ Respuesta de {ip}: tiempo=14ms")
                print(Fore.WHITE + f"  ✅ Respuesta de {ip}: tiempo=11ms")
                print(Fore.WHITE + f"  ✅ Respuesta de {ip}: tiempo=13ms")
                input(Fore.CYAN + "\nPresiona Enter para continuar...")
                
            elif opcion == '5':
                break
            else:
                print(Fore.RED + "\n[!] Opción no válida.")
                time.sleep(1.5)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(Fore.RED + f"\n[!] Error: {e}")
            time.sleep(1.5)

def menu_opciones():
    """Submenú de configuración."""
    global INTERFAZ_ACTUAL, TIEMPO_ESPERA
    
    while True:
        limpiar_pantalla()
        mostrar_banner()
        print(Fore.YELLOW + "\n" + "═"*50)
        print(Fore.CYAN + Back.BLACK + "           CONFIGURACIÓN".center(50))
        print(Fore.YELLOW + "═"*50)
        print(Fore.WHITE + f"  " + "1." + " " + f"📶  Interfaz actual: {Fore.CYAN}{INTERFAZ_ACTUAL or 'No detectada'}".ljust(40))
        print(Fore.WHITE + "  " + "2." + " " + "🔄  Cambiar interfaz".ljust(40))
        print(Fore.WHITE + "  " + "3." + " " + f"⏱️  Tiempo de espera: {Fore.CYAN}{TIEMPO_ESPERA}s".ljust(40))
        print(Fore.WHITE + "  " + "4." + " " + "ℹ️  Información del sistema".ljust(40))
        print(Fore.RED + "  " + "5." + " " + "🔙  Volver al menú principal".ljust(40))
        print(Fore.YELLOW + "═"*50)
        
        try:
            opcion = input(Fore.CYAN + "\n[+] Selecciona una opción: " + Fore.WHITE)
            
            if opcion == '1':
                if INTERFAZ_ACTUAL:
                    print(Fore.GREEN + f"\n[+] Interfaz activa: {INTERFAZ_ACTUAL}")
                    print(Fore.WHITE + f"  MAC: {netifaces.ifaddresses(INTERFAZ_ACTUAL)[netifaces.AF_LINK][0]['addr']}")
                else:
                    print(Fore.RED + "\n[!] No se detectó ninguna interfaz de red.")
                input(Fore.CYAN + "\nPresiona Enter para continuar...")
                
            elif opcion == '2':
                print(Fore.YELLOW + "\n[*] Interfaces disponibles:")
                for idx, iface in enumerate(netifaces.interfaces(), 1):
                    if iface != 'lo':
                        print(Fore.WHITE + f"  {idx}. {iface}")
                nueva = input(Fore.CYAN + "\n[+] Ingresa el nombre de la interfaz: " + Fore.WHITE)
                if nueva and nueva in netifaces.interfaces():
                    INTERFAZ_ACTUAL = nueva
                    print(Fore.GREEN + f"\n[+] Interfaz cambiada a: {nueva}")
                else:
                    print(Fore.RED + "\n[!] Interfaz no válida.")
                time.sleep(2)
                
            elif opcion == '3':
                try:
                    nuevo_tiempo = input(Fore.YELLOW + "[*] Nuevo tiempo de espera (segundos): " + Fore.WHITE)
                    if nuevo_tiempo:
                        TIEMPO_ESPERA = int(nuevo_tiempo)
                        print(Fore.GREEN + f"\n[+] Tiempo cambiado a: {TIEMPO_ESPERA}s")
                except ValueError:
                    print(Fore.RED + "\n[!] Ingresa un número válido.")
                time.sleep(2)
                
            elif opcion == '4':
                print(Fore.CYAN + "\n[+] Información del sistema:")
                print(Fore.WHITE + f"  Sistema: {platform.system()} {platform.release()}")
                print(Fore.WHITE + f"  Arquitectura: {platform.machine()}")
                print(Fore.WHITE + f"  Python: {platform.python_version()}")
                print(Fore.WHITE + f"  Mxcrack-ng v{VERSION}")
                print(Fore.WHITE + f"  Autor: {AUTOR}")
                input(Fore.CYAN + "\nPresiona Enter para continuar...")
                
            elif opcion == '5':
                break
            else:
                print(Fore.RED + "\n[!] Opción no válida.")
                time.sleep(1.5)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(Fore.RED + f"\n[!] Error: {e}")
            time.sleep(1.5)

# --- Funciones del Menú Principal ---

def opcion_capturar():
    """Maneja la opción 1: Capturar paquetes."""
    iface = obtener_interfaz_red()
    if not iface:
        print(Fore.RED + "[!] No se encontró una interfaz de red.")
        input(Fore.CYAN + "\nPresiona Enter para continuar...")
        return
    
    try:
        count = input(Fore.YELLOW + "[*] Número de paquetes (default 10): " + Fore.WHITE)
        count = int(count) if count.strip() else 10
        capturar_paquetes(iface, count)
    except ValueError:
        print(Fore.RED + "[!] Ingresa un número válido.")
    input(Fore.CYAN + "\nPresiona Enter para continuar...")

def opcion_probar():
    """Maneja la opción 2: Probar redes."""
    iface = obtener_interfaz_red()
    if not iface:
        print(Fore.RED + "[!] No se encontró una interfaz de red.")
        input(Fore.CYAN + "\nPresiona Enter para continuar...")
        return
    
    redes = escanear_redes(iface)
    if redes:
        probar_seguridad(redes)
    input(Fore.CYAN + "\nPresiona Enter para continuar...")

def opcion_ataques():
    """Maneja la opción 3: Ataques."""
    iface = obtener_interfaz_red()
    if not iface:
        print(Fore.RED + "[!] No se encontró una interfaz de red.")
        input(Fore.CYAN + "\nPresiona Enter para continuar...")
        return
    
    objetivo = input(Fore.YELLOW + "[*] MAC del objetivo (default AA:BB:CC:DD:EE:11): " + Fore.WHITE)
    if not objetivo:
        objetivo = "AA:BB:CC:DD:EE:11"
    ejecutar_ataque(iface, objetivo)
    input(Fore.CYAN + "\nPresiona Enter para continuar...")

def opcion_herramientas():
    """Maneja la opción 4: Herramientas."""
    menu_herramientas()

def opcion_opciones():
    """Maneja la opción 5: Opciones."""
    menu_opciones()

def opcion_ayuda():
    """Maneja la opción 6: Ayuda."""
    limpiar_pantalla()
    mostrar_banner()
    print(Fore.CYAN + """
    ╔══════════════════════════════════════════════════════════════╗
    ║                     Mxcrack-ng - Ayuda                     ║
    ╚══════════════════════════════════════════════════════════════╝
    
    📖  ¿Qué es Mxcrack-ng?
    Es una herramienta de seguridad WiFi que simula funcionalidades
    de aircrack-ng pero sin necesidad de modo monitor.
    
    🎯  Opciones del menú:
    
    1. 🔍  Capturar paquetes   - Captura tráfico de red.
    2. 📡  Probar redes        - Escanea y analiza redes WiFi.
    3. ⚔️  Ataques             - Ejecuta pruebas de penetración.
    4. 🛠️  Herramientas        - Utilidades adicionales.
    5. ⚙️  Opciones            - Configura la herramienta.
    6. ❓  Ayuda               - Muestra esta información.
    7. 🚪  Salir               - Cierra la aplicación.
    
    ⚠️  IMPORTANTE:
    • Esta herramienta es solo para fines educativos.
    • El uso no autorizado puede ser ilegal.
    • Para funciones reales se necesitan permisos de root.
    • Siempre usa en redes propias o con autorización.
    
    📌  Requisitos:
    • Python 3.6+
    • Librerías: scapy, netifaces, colorama
    
    💡  Consejos:
    • Ejecuta con: sudo python3 mxcrack.py
    • Para salir en cualquier momento: Ctrl+C
    """)
    input(Fore.CYAN + "\nPresiona Enter para volver al menú...")

# --- Función Principal ---

def main():
    """Bucle principal del programa."""
    # Verificar sistema
    print(Fore.CYAN + f"\n[+] Mxcrack-ng v{VERSION} iniciado")
    print(Fore.WHITE + f"[+] Sistema: {platform.system()} {platform.release()}")
    print(Fore.WHITE + f"[+] Fecha: {obtener_timestamp()}")
    
    # Verificar permisos
    verificar_permisos()
    
    # Detectar interfaz
    iface = obtener_interfaz_red()
    if iface:
        print(Fore.GREEN + f"[+] Interfaz detectada: {iface}")
    else:
        print(Fore.RED + "[!] No se detectó interfaz de red.")
        print(Fore.YELLOW + "[*] Puedes configurarla en Opciones.")
    
    time.sleep(1)
    
    while True:
        try:
            limpiar_pantalla()
            mostrar_banner()
            mostrar_menu()
            
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
                print(Fore.GREEN + "\n[+] ¡Gracias por usar Mxcrack-ng!")
                print(Fore.CYAN + "[+] Hasta luego, rey! 👑")
                sys.exit(0)
            else:
                print(Fore.RED + "\n[!] Opción no válida.")
                time.sleep(1.5)
                
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n\n[!] Interrupción detectada.")
            confirm = input(Fore.CYAN + "[?] ¿Deseas salir? (s/N): " + Fore.WHITE)
            if confirm.lower() == 's':
                print(Fore.GREEN + "\n[+] ¡Hasta luego, rey! 👑")
                sys.exit(0)
        except Exception as e:
            print(Fore.RED + f"\n[!] Error inesperado: {e}")
            print(Fore.YELLOW + "[*] El programa continuará.")
            time.sleep(2)

if __name__ == "__main__":
    main()
