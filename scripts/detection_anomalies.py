import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os
import sys
from colorama import init, Fore, Style

init(autoreset=True)

class AnomalyDetector:
    def __init__(self, input_file, output_file, model_file="models/isolation_forest.pkl"):
        self.input_file = input_file
        self.output_file = output_file
        self.model_file = model_file
        self.model = None
        self.df = None

    def load_data(self):
        """Chargement et pré-traitement des données"""
        print(f"{Fore.CYAN}[INFO] Chargement du dataset : {self.input_file}")
        
        if not os.path.exists(self.input_file):
            print(f"{Fore.RED}[ERREUR] Fichier introuvable. Lancez d'abord analyse_trafic.py")
            sys.exit(1)

        self.df = pd.read_csv(self.input_file)
        
        # Encoding du protocole (Categorical -> Numerical)
        self.df['protocol_code'] = self.df['protocol'].astype('category').cat.codes
        print(f"{Fore.GREEN}[OK] {len(self.df)} paquets chargés.")

    def train_model(self):
        """Entraînement de l'IA (Isolation Forest)"""
        print(f"{Fore.YELLOW}[AI] Entraînement du modèle Isolation Forest...")
        
        features = self.df[['packet_length', 'protocol_code']]
        
        # Contamination = % estimé d'anomalies (ex: 5%)
        self.model = IsolationForest(contamination=0.05, random_state=42, n_jobs=-1)
        self.df['anomaly'] = self.model.fit_predict(features)
        self.df['score'] = self.model.decision_function(features)
        
        # Sauvegarde du modèle (Optionnel pour réutilisation)
        os.makedirs(os.path.dirname(self.model_file), exist_ok=True)
        joblib.dump(self.model, self.model_file)
        print(f"{Fore.BLUE}[SAVE] Modèle IA sauvegardé sous : {self.model_file}")

    def classify_threats(self):
        """Classification avancée des menaces"""
        print(f"{Fore.MAGENTA}[LOGIC] Classification des types d'attaques...")
        
        conditions = [
            (self.df['anomaly'] == 1), # Normal
            (self.df['anomaly'] == -1) & (self.df['packet_length'] > 1500), # Large Packet
            (self.df['anomaly'] == -1) & (self.df['packet_length'] <= 1500) # Small Packet
        ]
        choices = ['Normal', 'Potential Data Exfiltration', 'Suspicious Scanning/Probe']
        
        self.df['Threat_Type'] = np.select(conditions, choices, default='Unknown')

    def save_results(self):
        """Exportation des résultats"""
        # Filtrer uniquement les anomalies pour le fichier de sortie
        anomalies = self.df[self.df['anomaly'] == -1]
        
        anomalies.to_csv(self.output_file, index=False)
        
        print(f"\n{Fore.GREEN}{Style.BRIGHT}[SUCCESS] Détection terminée !")
        print(f"{Fore.WHITE}" + "-"*40)
        print(f"{Fore.RED}🚨 Anomalies Détectées : {len(anomalies)}")
        print(f"{Fore.YELLOW}⚠️  Taux de Contamination : {(len(anomalies)/len(self.df)*100):.2f}%")
        print(f"{Fore.WHITE}" + "-"*40)
        print(f"{Fore.WHITE}📂 Rapport généré : {self.output_file}")

# --- Exécution ---
if __name__ == "__main__":
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    INPUT_CSV = os.path.join(BASE_DIR, "results", "traffic_stats.csv")
    OUTPUT_CSV = os.path.join(BASE_DIR, "results", "anomalies_detected.csv")
    MODEL_PATH = os.path.join(BASE_DIR, "models", "isolation_forest.pkl")

    detector = AnomalyDetector(INPUT_CSV, OUTPUT_CSV, MODEL_PATH)
    detector.load_data()
    detector.train_model()
    detector.classify_threats()
    detector.save_results()