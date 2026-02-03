import pyshark


cap = pyshark.FileCapture(
    r"C:\Users\HP\Desktop\systeme-supervision-reseau-anomalies\captures\testt1.pcapng"
)

print("📡 Paquets capturés :\n")

for packet in cap:
    try:
        print(
            "Source:", packet.ip.src,
            "→ Destination:", packet.ip.dst,
            "| Protocole:", packet.highest_layer
        )
    except:
        pass
