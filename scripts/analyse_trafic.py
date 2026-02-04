import pyshark
import pandas as pd
import os
import sys
from tqdm import tqdm
from colorama import init, Fore, Style

# Initialisation des couleurs
init(autoreset=True)

class TrafficAnalyzer:
    def __init__(self, pcap_file, output_file, tshark_path=None):
        self.pcap_file = pcap_file
        self.output_file = output_file
        self.tshark_path = tshark_path
        self._setup_environment()

    def _setup_environment(self):
        """Vérification des chemins et configuration"""
        print(f"{Fore.CYAN}[INFO] Initialisation du module d'analyse réseau...")
        
        if not os.path.exists(self.pcap_file):
            print(f"{Fore.RED}[ERREUR] Le fichier PCAP est introuvable : {self.pcap_file}")
            sys.exit(1)
            
        # Création du dossier results si inexistant
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)

    def process_capture(self):
        """Lecture et extraction des features du fichier PCAP"""
        print(f"{Fore.YELLOW}[RUN] Démarrage de l'extraction des paquets via TShark...")
        
        try:
            # Chargement avec Pyshark
            cap = pyshark.FileCapture(self.pcap_file, tshark_path=self.tshark_path, keep_packets=False)
            
            data = []
            # On ne peut pas connaître la taille exacte à l'avance avec pyshark stream, 
            # donc on utilise tqdm sans total ou on estime.
            print(f"{Fore.GREEN}[Wait] Lecture en cours... (Cela peut prendre un moment)")
            
            for packet in tqdm(cap, desc="Analyse des Paquets", unit="pkt"):
                try:
                    packet_info = {
                        "Time": packet.sniff_time,
                        "src_ip": packet.ip.src if hasattr(packet, 'ip') else "N/A",
                        "dst_ip": packet.ip.dst if hasattr(packet, 'ip') else "N/A",
                        "protocol": packet.highest_layer,
                        "packet_length": int(packet.length),
                        "info": str(packet).split('\n')[0] # Résumé rapide
                    }
                    data.append(packet_info)
                except AttributeError:
                    continue # Ignorer les paquets mal formés
            
            cap.close()
            self._save_to_csv(data)

        except Exception as e:
            print(f"{Fore.RED}[CRASH] Erreur critique lors de l'analyse : {e}")

    def _save_to_csv(self, data):
        """Sauvegarde des résultats en CSV"""
        if not data:
            print(f"{Fore.RED}[AVERTISSEMENT] Aucun paquet capturé ou fichier vide.")
            return

        df = pd.DataFrame(data)
        df.to_csv(self.output_file, index=False)
        
        print(f"\n{Fore.GREEN}{Style.BRIGHT}[SUCCESS] Analyse terminée !")
        print(f"{Fore.WHITE}📊 Total Paquets : {len(df)}")
        print(f"{Fore.WHITE}💾 Données sauvegardées dans : {self.output_file}")

# --- Exécution ---
if __name__ == "__main__":
    # Configuration des chemins (Modifier si nécessaire)
    PCAP_PATH = r"captures\testt1.pcapng" # Chemin relatif
    OUTPUT_PATH = r"results\traffic_stats.csv"
    
    # Chemin absolu pour éviter les erreurs
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    PCAP_FULL = os.path.join(BASE_DIR, PCAP_PATH)
    OUTPUT_FULL = os.path.join(BASE_DIR, OUTPUT_PATH)
    
    # TShark Path (Optionnel, Pyshark le trouve souvent seul)
    # TSHARK = r"C:\Program Files\Wireshark\tshark.exe"

    analyzer = TrafficAnalyzer(PCAP_FULL, OUTPUT_FULL)
    analyzer.process_capture()