import netifaces as ni
from scapy.all import *
import threading
from datetime import datetime
import pandas as pd

# Variables globales para almacenar estadísticas
total_paquetes = 0
ip_contador = {}
protocolos_usados = {}

# Lista para almacenar detalles de paquetes
detalles_paquetes = []

# Función para obtener las interfaces de red disponibles
def obtener_interfaces_red():
    interfaces = ni.interfaces()
    return interfaces

# Función para convertir el número de protocolo a nombre del protocolo
def obtener_nombre_protocolo(numero_protocolo):
    protocolos = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        47: "GRE",
        # Puedes añadir más protocolos según sea necesario
    }
    return protocolos.get(numero_protocolo, "Otro")

# Función para convertir el Ethertype a un nombre legible
def obtener_nombre_ethertype(ethertype):
    ethertypes = {
        0x0800: "IPv4",
        0x86DD: "IPv6",
        0x0806: "ARP",
        # Puedes añadir más Ethertypes según sea necesario
    }
    return ethertypes.get(ethertype, "Otro")

# Función para procesar y mostrar los paquetes capturados
def procesar_paquete(pkt):
    global total_paquetes, ip_contador, protocolos_usados, detalles_paquetes
    
    if IP in pkt or ARP in pkt:
        total_paquetes += 1
        ip_origen = pkt[IP].src if IP in pkt else pkt[ARP].psrc
        ip_destino = pkt[IP].dst if IP in pkt else pkt[ARP].pdst
        ethertype = pkt[Ether].type if Ether in pkt else 0x0806  # 0x0806 es el Ethertype para ARP
        ethertype_texto = obtener_nombre_ethertype(ethertype)
        protocolo_num = pkt[IP].proto if IP in pkt else None
        protocolo_texto = obtener_nombre_protocolo(protocolo_num) if IP in pkt else "ARP"
        
        # Añadir lógica para HTTP y DNS
        if TCP in pkt:
            if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                protocolo_texto = "HTTP"
            elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                protocolo_texto = "HTTPS"
        elif UDP in pkt:
            if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                protocolo_texto = "DNS"
        elif ICMP in pkt:
            protocolo_texto = "ICMP"

        puerto_origen = pkt.sport if TCP in pkt or UDP in pkt else 'N/A'
        puerto_destino = pkt.dport if TCP in pkt or UDP in pkt else 'N/A'
        
        # Contar IP de origen para calcular porcentaje
        if ip_origen in ip_contador:
            ip_contador[ip_origen] += 1
        else:
            ip_contador[ip_origen] = 1

        # Actualizar estadísticas de protocolos usados
        if protocolo_texto in protocolos_usados:
            protocolos_usados[protocolo_texto] += 1
        else:
            protocolos_usados[protocolo_texto] = 1

        # Guardar detalles del paquete
        detalles_paquetes.append({
            'IP Origen': ip_origen,
            'IP Destino': ip_destino,
            'Ethertype': ethertype_texto,
            'Protocolo': protocolo_texto,
            'Puerto Origen': puerto_origen,
            'Puerto Destino': puerto_destino
        })

        # Mostrar los datos en forma de tabla en la terminal
        print(f"| {ip_origen:<15} | {ip_destino:<15} | {ethertype_texto:<10} | {protocolo_texto:<9} | {puerto_origen:<12} | {puerto_destino:<12} |")

# Función para escanear la red en una interfaz específica
def escanear_red(interfaz, tiempo_escaneo):
    sniff(iface=interfaz, prn=procesar_paquete, store=0, timeout=tiempo_escaneo)

# Función para ejecutar el escaneo en un hilo
def ejecutar_escaneo(interfaz, tiempo_escaneo):
    thread_escaneo = threading.Thread(target=escanear_red, args=(interfaz, tiempo_escaneo))
    thread_escaneo.start()
    thread_escaneo.join(tiempo_escaneo)

# Función para guardar estadísticas en un archivo Excel
def guardar_en_excel():
    # Convertir detalles de paquetes a DataFrame de pandas
    df_detalles = pd.DataFrame(detalles_paquetes)

    # Calcular porcentaje de IP más utilizadas
    total_ips = sum(ip_contador.values())
    porcentaje_ips = {ip: round((count / total_ips * 100), 2) for ip, count in ip_contador.items()}

    # Convertir estadísticas generales a DataFrames de pandas
    df_protocolos = pd.DataFrame(list(protocolos_usados.items()), columns=['Protocolo', 'Cantidad'])
    df_ips = pd.DataFrame(list(ip_contador.items()), columns=['IP', 'Cantidad'])

    # Guardar en Excel
    archivo_excel = f'resultados.xlsx'
    with pd.ExcelWriter(archivo_excel) as writer:
        df_detalles.to_excel(writer, sheet_name='Detalles', index=False)
        df_protocolos.to_excel(writer, sheet_name='Protocolos', index=False)
        df_ips.to_excel(writer, sheet_name='IPs', index=False)

    print(f'Datos guardados en {archivo_excel}')

# Función principal del programa
if __name__ == "__main__":
    interfaces = obtener_interfaces_red()
    
    if not interfaces:
        print("No se encontraron interfaces de red disponibles.")
    else:
        print("Interfaces de red disponibles:")
        for i, interfaz in enumerate(interfaces, start=1):
            print(f"{i}. {interfaz}")
        
        seleccion = input("Seleccione el número de la interfaz para escanear (por ejemplo, '1'): ")
        try:
            seleccion = int(seleccion)
            interfaz_seleccionada = interfaces[seleccion - 1]
            
            tiempo_escaneo = input("Ingrese la duración del escaneo en segundos: ")
            tiempo_escaneo = int(tiempo_escaneo)
            
            print(f"Escaneando red en la interfaz {interfaz_seleccionada} durante {tiempo_escaneo} segundos...")
            print(f"| {'IP Origen':<15} | {'IP Destino':<15} | {'Ethertype':<10} | {'Protocolo':<9} | {'Puerto Origen':<12} | {'Puerto Destino':<12} |")
            print("-" * 90)

            ejecutar_escaneo(interfaz_seleccionada, tiempo_escaneo)

            # Llamar a la función para guardar en Excel
            guardar_en_excel()

        except (IndexError, ValueError):
            print("Selección inválida.")
