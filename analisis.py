import pandas as pd
import json

# Leer datos desde un archivo Excel
file_path = 'resultados.xlsx'
df = pd.read_excel(file_path)

# Análisis de protocolo más utilizado
protocol_count = df['Protocolo'].value_counts(normalize=True, ascending=False) * 100
protocol_labels = protocol_count.index.tolist()
protocol_data = protocol_count.round(0).astype(int).tolist()
print("Protocolos más utilizados:")
for label, data in zip(protocol_labels, protocol_data):
    print(f"{label}: {data}%")

# Frecuencia de tráfico por IP de origen y destino
ip_origen_count = df['IP Origen'].value_counts(normalize=True, ascending=False) * 100
ip_destino_count = df['IP Destino'].value_counts(normalize=True, ascending=False) * 100
ip_labels = ip_origen_count.index.tolist()
ip_data = ip_origen_count.round(0).astype(int).tolist()
print("\nFrecuencia de tráfico por IP (Origen):")
for label, data in zip(ip_labels[:3], ip_data[:3]):
    print(f"{label}: {data}%")

# Distribución de tipos de Ethertype
ethertype_count = df['Ethertype'].value_counts(normalize=True, ascending=False) * 100
ethertype_labels = ethertype_count.index.tolist()
ethertype_data = ethertype_count.round(0).astype(int).tolist()
print("\nDistribución de tipos de Ethertype:")
for label, data in zip(ethertype_labels, ethertype_data):
    print(f"{label}: {data}%")

# Detección de tráfico anómalo (múltiples solicitudes ARP)
arp_requests = df[df['Protocolo'] == 'ARP']
arp_request_count = arp_requests['IP Origen'].value_counts()
arp_labels = arp_request_count.index.tolist()
arp_data = arp_request_count.round(0).astype(int).tolist()
print("\nConsultas ARP más frecuentes:")
for label, data in zip(arp_labels[:3], arp_data[:3]):
    print(f"{label}: {data}")

# Obtener la IP con mayor cantidad de solicitudes ARP
if arp_labels:
    ip_max_arp = arp_labels[0]  # Tomamos la primera IP (la que tiene más solicitudes ARP)
    print(f"\nIP con más solicitudes ARP: {ip_max_arp}")
else:
    ip_max_arp = "No se encontraron solicitudes ARP"
    print(f"\n{ip_max_arp}")

# Calcular porcentajes sobre el total como enteros
total_count = df.shape[0]
udp_count = df[df['Puerto Origen'] == 53].shape[0] + df[df['Puerto Destino'] == 53].shape[0]
http_count = df[df['Puerto Origen'] == 80].shape[0] + df[df['Puerto Destino'] == 80].shape[0]
https_count = df[df['Puerto Origen'] == 443].shape[0] + df[df['Puerto Destino'] == 443].shape[0]
tcp_count = total_count - udp_count - http_count - https_count
udp_percentage = round((udp_count / total_count) * 100)
tcp_percentage = round((tcp_count / total_count) * 100)
total_percentage = udp_percentage + tcp_percentage
if total_percentage != 100:
    if udp_percentage > tcp_percentage:
        udp_percentage -= total_percentage - 100
    else:
        tcp_percentage -= total_percentage - 100

print(f"\nPorcentaje de tráfico UDP: {udp_percentage}%")
print(f"Porcentaje de tráfico TCP: {tcp_percentage}%")

# Preparar estructura JSON
data_json = {
    "protocolosData": {
        "labels": protocol_labels,
        "datasets": [{
            "label": "Protocolos",
            "data": protocol_data,
            "backgroundColor": ["#007bff", "#28a745", "#ffc107", "#dc3545"]
        }]
    },
    "trafficData": {
        "labels": ip_labels[:3],
        "datasets": [{
            "label": "Tráfico",
            "data": ip_data[:3],
            "backgroundColor": ["#007bff", "#28a745", "#ffc107"]
        }]
    },
    "trafficTypeData": {
        "labels": ethertype_labels,
        "datasets": [{
            "label": "Tipos de Tráfico",
            "data": ethertype_data,
            "backgroundColor": ["#007bff", "#28a745", "#ffc107", "#dc3545"]
        }]
    },
    "arpScanData": {
        "labels": arp_labels[:3],
        "datasets": [{
            "label": "Consultas ARP",
            "data": arp_data[:3],
            "backgroundColor": ["#007bff", "#28a745", "#ffc107"]
        }]
    },
    "udpTcpData": {
        "labels": ["UDP", "TCP"],
        "datasets": [{
            "label": "UDP vs TCP",
            "data": [udp_percentage, tcp_percentage],
            "backgroundColor": ["#007bff", "#28a745"]
        }]
    },
    "rojo": ip_max_arp  # Agregamos la variable "rojo"
}

# Guardar datos en archivo JSON
json_file_path = 'data.json'
with open(json_file_path, 'w') as json_file:
    json.dump(data_json, json_file, indent=4)

print(f"\nDatos guardados exitosamente en {json_file_path}")
