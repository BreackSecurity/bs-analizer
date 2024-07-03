import pyshark
from collections import Counter
from tabulate import tabulate

def analyze_pcap_for_ddos(file_path):
    cap = pyshark.FileCapture(file_path)
    
    # Contador para almacenar las solicitudes por IP
    ip_counter = Counter()

    # Itera a través de los paquetes capturados
    for pkt in cap:
        if 'IP' in pkt:
            src_ip = pkt.ip.src
            ip_counter[src_ip] += 1
    
    # Filtrar IPs que exceden un umbral (por ejemplo, 1000 solicitudes)
    ddos_threshold = 1000
    potential_ddos = {ip: count for ip, count in ip_counter.items() if count > ddos_threshold}

    # Imprime la tabla utilizando tabulate
    headers = ["ip origen", "solicitudes"]
    print(tabulate(potential_ddos.items(), headers=headers, tablefmt="grid"))

def analyze_pcap_for_port_scan(file_path):
    cap = pyshark.FileCapture(file_path)
    
    port_counter = Counter()
    
    for pkt in cap:
        if 'TCP' in pkt:
            src_ip = pkt.ip.src
            dst_port = pkt.tcp.dstport
            port_counter[(src_ip, dst_port)] += 1
    
    # Filtrar IPs que intentan múltiples puertos (por ejemplo, más de 20 puertos diferentes)
    port_scan_threshold = 20
    potential_scans = [ip for ip, count in Counter([src_ip for src_ip, dst_port in port_counter]).items() if count > port_scan_threshold]
    
    # Imprime la lista de posibles escaneos de puertos
    print(tabulate([[ip] for ip in potential_scans], headers=["IP origen"], tablefmt="grid"))

def analyze_pcap_for_protocols(file_path):
    cap = pyshark.FileCapture(file_path)
    
    protocol_counter = Counter()
    
    for pkt in cap:
        protocol = pkt.highest_layer
        protocol_counter[protocol] += 1
    
    # Imprime la tabla utilizando tabulate
    headers = ["Protocolo", "Cantidad de paquetes"]
    print(tabulate(protocol_counter.items(), headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    file_path = 'ARCHIVO.pcap'  # Reemplaza con la ruta de tu archivo pcap
    
    print("Análisis de posibles ataques DDoS...")
    analyze_pcap_for_ddos(file_path)
    
    print("\nAnálisis de posibles escaneos de puertos...")
    analyze_pcap_for_port_scan(file_path)
    
    print("\nAnálisis del uso del protocolo...")
    analyze_pcap_for_protocols(file_path)
