import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_option_menu import option_menu
from sklearn.ensemble import IsolationForest
import numpy as np
import os

# ---------------------------------------------------------
# 1. CONFIGURATION DE LA PAGE
# ---------------------------------------------------------
st.set_page_config(
    page_title="SOC | Nada Fajri",
    page_icon="🛡️",
    layout="wide"
)

# CSS Customisé (Dark Mode & Cyberpunk Style)
st.markdown("""
    <style>
        /* Global Background */
        .stApp {background-color: #0E1117; color: #FAFAFA;}
        
        /* KPI Cards */
        div[data-testid="metric-container"] {
            background-color: #1E2130;
            border-left: 5px solid #00FF41;
            padding: 10px;
            border-radius: 5px;
            box-shadow: 2px 2px 10px rgba(0,0,0,0.5);
        }
        
        /* Tables */
        .stDataFrame {border: 1px solid #30363d;}
        
        /* Links */
        a {text-decoration: none; color: #00FF41 !important;}
        
        /* Footer */
        .footer {
            position: fixed; bottom: 0; left: 0; width: 100%;
            background-color: #161B22; color: #8b949e;
            text-align: center; padding: 10px; font-size: 13px;
            border-top: 1px solid #30363d; z-index: 100;
        }
    </style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# 2. CHARGEMENT DES DONNÉES & IA
# ---------------------------------------------------------
@st.cache_data
def load_data():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    file_path = os.path.join(project_root, "results", "traffic_stats.csv")
    
    if not os.path.exists(file_path):
        return None

    df = pd.read_csv(file_path)
    df['Time'] = pd.date_range(start='2024-01-01', periods=len(df), freq='S')
    
    # التأكد من وجود الأعمدة لتفادي الأخطاء
    if 'src_ip' not in df.columns:
        df['src_ip'] = "N/A"
    if 'dst_ip' not in df.columns:
        df['dst_ip'] = "N/A"

    # IA Simulation (Isolation Forest)
    df['protocol_code'] = df['protocol'].astype('category').cat.codes
    model = IsolationForest(contamination=0.04, random_state=42)
    df['anomaly'] = model.fit_predict(df[['packet_length', 'protocol_code']])
    
    # Classification des menaces
    conditions = [
        (df['anomaly'] == 1),
        (df['anomaly'] == -1) & (df['packet_length'] > 1000),
        (df['anomaly'] == -1) & (df['packet_length'] <= 1000)
    ]
    choices = ['Normal', 'Potential Data Exfiltration', 'Suspicious Scanning']
    df['Threat_Type'] = np.select(conditions, choices, default='Unknown')
    
    return df

df = load_data()

# ---------------------------------------------------------
# 3. SIDEBAR NAVIGATION
# ---------------------------------------------------------
with st.sidebar:
    st.title("🛡️ SOC CONTROL")
    st.caption("Developed by Nada Fajri")
    
    # Menu
    selected = option_menu(
        menu_title=None,
        options=["Accueil", "Tableau de Bord", "Logs & Données", "À propos"],
        icons=["house", "speedometer2", "database", "person-badge"],
        menu_icon="cast",
        default_index=0,
        styles={
            "container": {"padding": "0!important", "background-color": "#161B22"},
            "icon": {"color": "#00FF41", "font-size": "18px"}, 
            "nav-link": {"font-size": "16px", "text-align": "left", "margin":"0px", "--hover-color": "#21262d"},
            "nav-link-selected": {"background-color": "#238636"},
        }
    )
    
    st.markdown("---")
    st.markdown("### 📡 Status")
    st.success("System Online")

# ---------------------------------------------------------
# 4. PAGE 1 : ACCUEIL
# ---------------------------------------------------------
if selected == "Accueil":
    st.title("🌐 Bienvenue au Centre de Supervision")
    st.markdown("### Projet de Fin d'Études : Détection d'Intrusions par IA")
    
    c1, c2 = st.columns([2, 1])
    with c1:
        st.markdown("""
        Ce système permet de **surveiller le trafic réseau** et de détecter les comportements suspects (anomalies) grâce à l'Intelligence Artificielle.
        
        **Fonctionnalités Clés :**
        * 🕵️‍♂️ **Sniffing :** Capture des paquets en temps réel.
        * 🧠 **IA :** Algorithme *Isolation Forest* pour détecter les intrusions.
        * 📊 **Visualisation :** Tableaux de bord interactifs pour l'analyse.
        """)
    with c2:
        if df is not None:
             st.metric("Total Paquets Capturés", len(df))
             st.metric("Protocoles Identifiés", df['protocol'].nunique())

# ---------------------------------------------------------
# 5. PAGE 2 : TABLEAU DE BORD (DASHBOARD)
# ---------------------------------------------------------
elif selected == "Tableau de Bord":
    if df is None:
        st.error("⚠️ Veuillez lancer l'analyse du trafic d'abord (analyse_trafic.py).")
    else:
        st.title("📊 Tableau de Bord Analytique")
        
        # KPIs
        total = len(df)
        anomalies = df[df['anomaly'] == -1]
        risk = (len(anomalies)/total * 100) if total > 0 else 0
        
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("📦 Trafic Total", total)
        k2.metric("🚨 Menaces", len(anomalies), delta_color="inverse")
        k3.metric("⚠️ Risque Global", f"{risk:.2f}%", delta_color="inverse")
        k4.metric("🛡️ Protocole Dominant", df['protocol'].mode()[0])
        
        st.markdown("---")
        
        # Graphs
        g1, g2 = st.columns([2, 1])
        with g1:
            st.subheader("Flux Réseau & Anomalies")
            fig_area = px.area(df, x='Time', y='packet_length', color='Threat_Type',
                            color_discrete_map={'Normal': '#00CC96', 'Potential Data Exfiltration': '#EF553B', 'Suspicious Scanning': '#FFA15A'})
            fig_area.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="white"))
            st.plotly_chart(fig_area, use_container_width=True)
            
        with g2:
            st.subheader("Type d'Attaques")
            if not anomalies.empty:
                # CORRECTION 1: px.pie instead of px.doughnut
                fig_pie = px.pie(anomalies, names='Threat_Type', hole=0.4, color_discrete_sequence=px.colors.sequential.RdBu)
                fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)", font=dict(color="white"), showlegend=False)
                st.plotly_chart(fig_pie, use_container_width=True)

# ---------------------------------------------------------
# 6. PAGE 3 : LOGS & DONNÉES
# ---------------------------------------------------------
elif selected == "Logs & Données":
    st.title("📂 Journaux de Sécurité (Logs)")
    
    if df is not None:
        tab1, tab2 = st.tabs(["🔴 Menaces Détectées", "🟢 Tout le Trafic"])
        
        with tab1:
            anomalies = df[df['anomaly'] == -1]
            st.warning(f"{len(anomalies)} paquets suspects identifiés.")
            # CORRECTION 2: Columns adjusted to prevent KeyError
            cols_to_show = ['Time', 'protocol', 'packet_length', 'Threat_Type']
            if 'src_ip' in df.columns: cols_to_show.insert(1, 'src_ip')
            if 'dst_ip' in df.columns: cols_to_show.insert(2, 'dst_ip')
            
            st.dataframe(anomalies[cols_to_show], use_container_width=True)
            
        with tab2:
            st.dataframe(df, use_container_width=True)

# ---------------------------------------------------------
# 7. PAGE 4 : À PROPOS (NADA FAJRI)
# ---------------------------------------------------------
elif selected == "À propos":
    st.title("ℹ️ À propos du Projet")
    
    col_profile, col_info = st.columns([1, 2])
    
    with col_profile:
        # Icone de profil
        st.image("https://cdn-icons-png.flaticon.com/512/4333/4333609.png", width=150)
    
    with col_info:
        st.markdown("""
        ### 👩‍💻 Etudiante
        **Nom :** Nada Fajri  
        **Rôle :** Etudiante en génie informatique  
        
        ---
        ### 🔗 Contact & Code
        * **GitHub :** [github.com/fajrin353-beep](https://github.com/fajrin353-beep)
        * **Projet :** Network Anomaly Detection System (NADS)
        """)
        
    st.success("Projet validé pour le PFE - Session 2026.")

# ---------------------------------------------------------
# FOOTER GLOBAL
# ---------------------------------------------------------
st.markdown("""
    <div class="footer">
        🔒 SOC Monitoring System | PFE 2026 | Developed by <b>Nada Fajri</b> (@fajrin353-beep)
    </div>
""", unsafe_allow_html=True)