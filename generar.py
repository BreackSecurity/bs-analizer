import pandas as pd
import json

def analyze_network_data(filename):
    try:
        # Leer el archivo Excel
        df = pd.read_excel(filename)
    except FileNotFoundError:
        print(f"El archivo '{filename}' no se encontró.")
        return
    
    # Análisis de protocolos
    protocol_counts = df['Protocolo'].value_counts(normalize=True) * 100
    protocol_counts = protocol_counts.round(2)  # Redondear porcentaje a 2 decimales

    # Análisis de tráfico por IP de origen y destino
    traffic_by_source_ip = df.groupby('IP Origen')['Tamaño del Paquete'].sum().sort_values(ascending=False)
    traffic_by_dest_ip = df.groupby('IP Destino')['Tamaño del Paquete'].sum().sort_values(ascending=False)

    # Análisis de tamaño de paquetes
    packet_sizes = {
        'Tamaño Máximo': df['Tamaño del Paquete'].max(),
        'Tamaño Mínimo': df['Tamaño del Paquete'].min(),
        'Tamaño Promedio': df['Tamaño del Paquete'].mean().round(2),
        'Total Paquetes': len(df),
    }

    # Preparar datos para guardar en JSON
    data = {
        'Protocolos': protocol_counts.to_dict(),
        'Tráfico por IP de Origen': traffic_by_source_ip.head(1).to_dict(),  # Solo la IP de origen con más tráfico
        'Tráfico por IP de Destino': traffic_by_dest_ip.head(1).to_dict(),  # Solo la IP de destino con más tráfico
        'Tamaños de Paquetes': packet_sizes,
    }

    # Guardar datos en un archivo JSON
    json_filename = 'analisis_red.json'
    with open(json_filename, 'w') as json_file:
        json.dump(data, json_file, indent=4)

    print(f"Análisis de red completado. Datos guardados en '{json_filename}'.")

# Nombre del archivo Excel con los datos de red
excel_file = 'capturas_2024-07-02_10-22-48.xlsx'

# Llamar a la función para realizar el análisis
analyze_network_data(excel_file)
