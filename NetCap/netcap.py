# netcap.py
import os
from scapy.all import sniff, wrpcap, get_if_list
import configparser

# ======== CONFIG ========
config_path = os.path.join("configs", "config.ini")
config = configparser.ConfigParser()
config.read(config_path)

# Interfaz a capturar
iface = config.get("capture", "interface", fallback=None)
# Número de paquetes a capturar (si duration = 0, captura infinita)
packet_count = config.getint("capture", "packet_count", fallback=50)
# Archivo de salida
archivo = config.get("capture", "outfile", fallback="captura.pcap")

# Validar interfaz
interfaces = get_if_list()
if iface not in interfaces:
    print(f"Interfaz {iface} no encontrada. Interfaces disponibles:")
    for i in interfaces:
        print(f" - {i}")
    exit(1)

print(f"Capturando en interfaz: {iface}")
print(f"Número de paquetes: {packet_count}")
print(f"Archivo de salida: {os.path.abspath(archivo)}")

# ======== FUNCION DE CAPTURA ========
def guardar_paquetes(paquetes):
    wrpcap(archivo, paquetes)
    print(f"Captura finalizada. Archivo guardado en: {os.path.abspath(archivo)}")

# Captura paquetes
paquetes = sniff(iface=iface, count=packet_count)
guardar_paquetes(paquetes)
