import scapy.all as scapy
import netifaces
import time

def get_network_interface():
    interfaces = netifaces.interfaces()
    print("Interfaces de red disponibles:")
    for i, interface in enumerate(interfaces):
        print(f"{i+1}. {interface}")
    while True:
        try:
            choice = int(input("Seleccione el número de la interfaz de red: "))
            if choice < 1 or choice > len(interfaces):
                print("Selección no válida. Intente nuevamente.")
            else:
                return interfaces[choice-1]
        except ValueError:
            print("Por favor, ingrese un número válido.")

def scan_network(interface):
    network = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    subnet = network + "/24"
    print(f"Escaneando la red {subnet}...")
    arp_request = scapy.ARP(pdst=subnet)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    ips = []
    print("Direcciones IP en la red:")
    print("Índice\t\tIP\t\t\tMAC Address")
    print("-----------------------------------------")
    for i, element in enumerate(answered_list):
        ip = element[1].psrc
        mac = element[1].hwsrc
        print(f"{i+1}\t\t{ip}\t\t{mac}")
        ips.append(ip)
    
    return ips

def traffic_monitor(ip, interface, duration=10):
    print(f"Iniciando monitoreo de tráfico para la IP {ip} en la interfaz {interface} durante {duration} segundos...")
    start_time = time.time()
    while (time.time() - start_time) < duration:
        scapy.sniff(iface=interface, filter=f"host {ip}", prn=process_packet)

def process_packet(packet):
    print(packet.show())

def main():
    interface = get_network_interface()
    while True:
        print("\nMenú:")
        print("1. Escanear red")
        print("2. Monitorear tráfico de una IP")
        print("3. Salir")
        choice = input("Seleccione una opción: ")
        if choice == '1':
            ips = scan_network(interface)
        elif choice == '2':
            if not ips:
                print("Primero debes escanear la red.")
                continue
            print("Seleccione la IP para monitorear:")
            for i, ip in enumerate(ips):
                print(f"{i+1}. {ip}")
            try:
                ip_choice = int(input("Ingrese el número de la IP: "))
                if ip_choice < 1 or ip_choice > len(ips):
                    print("Selección no válida.")
                    continue
                selected_ip = ips[ip_choice - 1]
                duration = int(input("Ingrese la duración del monitoreo en segundos: "))
                traffic_monitor(selected_ip, interface, duration)
            except ValueError:
                print("Por favor, ingrese un número válido.")
        elif choice == '3':
            break
        else:
            print("Opción no válida. Intente nuevamente.")

if __name__ == "__main__":
    main()
