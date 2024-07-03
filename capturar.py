import pyshark
import scapy.all as scapy

def get_network_interfaces():
    """
    Obtiene una lista de todas las interfaces de red disponibles.
    """
    interfaces = scapy.ifaces.data.keys()
    return list(interfaces)

def select_network_interface(interfaces):
    """
    Permite al usuario seleccionar una interfaz de red de una lista.
    """
    print("Interfaces de red disponibles:")
    for i, interface in enumerate(interfaces):
        print(f"{i + 1}. {interface}")

    choice = input("Seleccione una interfaz: ")
    try:
        choice = int(choice) - 1
        if 0 <= choice < len(interfaces):
            return interfaces[choice]
        else:
            print("Opción no válida.")
            return None
    except ValueError:
        print("Opción no válida.")
        return None

def capture_traffic(interface, packet_count):
    """
    Captura el tráfico de la red en la interfaz especificada hasta capturar la cantidad indicada de paquetes.
    """
    # Crear un objeto LiveCapture para iniciar la captura en la interfaz especificada
    capture = pyshark.LiveCapture(interface=interface)

    # Definir la función de devolución de llamada para cada paquete capturado
    def packet_callback(pkt):
        print(pkt)

    # Aplicar la función de devolución de llamada a cada paquete capturado
    capture.apply_on_packets(packet_callback)

    try:
        capture.sniff(packet_count=packet_count)
    except KeyboardInterrupt:
        print("Captura detenida manualmente.")

def main():
    """
    Función principal que ejecuta el flujo del programa.
    """
    interfaces = get_network_interfaces()
    if not interfaces:
        print("No se encontraron interfaces de red.")
        return

    selected_interface = select_network_interface(interfaces)
    if not selected_interface:
        return

    while True:
        packet_count = input("Ingrese la cantidad de paquetes a capturar (0 para captura infinita): ")
        try:
            packet_count = int(packet_count)
            if packet_count >= 0:
                break
            else:
                print("Ingrese un número positivo o 0.")
        except ValueError:
            print("Ingrese un número válido.")

    if packet_count == 0:
        packet_count = None

    print(f"Capturando tráfico en la interfaz: {selected_interface} hasta capturar {packet_count} paquetes.")
    capture_traffic(selected_interface, packet_count)

if __name__ == "__main__":
    main()

