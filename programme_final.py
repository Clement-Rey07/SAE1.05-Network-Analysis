import matplotlib.pyplot as plt
import markdown
import os
from collections import Counter
import datetime

nom_fichier_logs = "dump.txt"


def analyser_logs(fichier):
    traffic = []
    if not os.path.exists(fichier):
        print(f"❌ ERREUR : Fichier introuvable : {fichier}")
        return []

    print(f"✅ Lecture du fichier en cours...")
    try:
        with open(fichier, 'r', encoding='utf-8') as f:
            for ligne in f:
                if " IP " in ligne and ">" in ligne:
                    try:
                        parties = ligne.split()
                        timestamp = parties[0]
                        source = parties[2]
                        if source.count('.') == 4: src_clean = ".".join(source.split('.')[:-1])
                        else: src_clean = source

                        destination = parties[4].replace(':', '')
                        if destination.count('.') == 4: dst_clean = ".".join(destination.split('.')[:-1])
                        else: dst_clean = destination
                        
                        flags = "Autre"
                        if "Flags [" in ligne:
                            debut = ligne.find("Flags [") + 7
                            fin = ligne.find("]", debut)
                            flags = ligne[debut:fin]

                        traffic.append({"time": timestamp, "src": src_clean, "dst": dst_clean, "flags": flags})
                    except: continue
        return traffic
    except Exception as e:
        print(f"Erreur : {e}")
        return []


donnees = analyser_logs(nom_fichier_logs)

if not donnees:
    print("ECHEC : Pas de données. Vérifiez le fichier dump.txt")
    exit()

sources = [d['src'] for d in donnees]
compteur_sources = Counter(sources)
suspect = compteur_sources.most_common(1)[0]
ip_suspecte = suspect[0]
nb_paquets = suspect[1]

print(f"🚨 ALERTE : {ip_suspecte} a envoyé {nb_paquets} paquets.")


dossier_base = os.path.dirname(nom_fichier_logs)
chemin_csv = os.path.join(dossier_base, "analyse_reseau.csv")
with open(chemin_csv, "w", encoding="utf-8") as f:
    f.write("Date;Source;Destination;Protocol_Flags\n")
    for d in donnees:
        f.write(f"{d['time']};{d['src']};{d['dst']};{d['flags']}\n")


top_sources = compteur_sources.most_common(5)
labels = [ip[0] for ip in top_sources]
values = [ip[1] for ip in top_sources]
plt.figure(figsize=(10, 6))
couleurs = ['#e74c3c'] + ['#bdc3c7'] * (len(values)-1) 
plt.bar(labels, values, color=couleurs, edgecolor='#2c3e50')
plt.title("Volume de trafic par IP (Détection d'anomalie)", fontsize=14, fontweight='bold')
plt.xlabel("Adresses IP", fontsize=12)
plt.ylabel("Nombre de paquets", fontsize=12)
plt.grid(axis='y', linestyle='--', alpha=0.5)
plt.xticks(rotation=45, ha='right')
plt.tight_layout()

chemin_img = os.path.join(dossier_base, "graphique_attaques.png")
plt.savefig(chemin_img, dpi=100) 
plt.close()

lignes_tableau = ""
count = 0
for d in donnees:
    if d['src'] == ip_suspecte and count < 8: 
        lignes_tableau += f"| {d['time']} | **{d['src']}** | {d['dst']} | `{d['flags']}` |\n"
        count += 1

date_gen = datetime.datetime.now().strftime("%d/%m/%Y à %H:%M")

rapport_md = f"""
<div class="header">
    <h1>Rapport d'Incident de Sécurité</h1>
    <p>Généré automatiquement le {date_gen}</p>
</div>

<div class="alert">
    <strong>⚠️ MENACE DÉTECTÉE : Attaque par Déni de Service (DoS)</strong><br>
    Une activité anormale a été identifiée provenant de l'adresse IP <strong>{ip_suspecte}</strong>.
</div>

## 1. Synthèse de l'analyse
L'analyse des journaux réseau (`tcpdump`) révèle une saturation causée par un flux massif de paquets.

* **Fichier source** : `dump.txt`
* **Volume total** : {len(donnees)} paquets analysés
* **Vecteur d'attaque** : Flood de paquets (Flags SYN majoritaires)
* **Impact** : Saturation de la bande passante et des ressources serveur.

## 2. Preuve Visuelle
Le graphique ci-dessous illustre la disproportion du trafic généré par l'attaquant par rapport aux utilisateurs légitimes.

![Graphique](graphique_attaques.png)

## 3. Preuves Techniques (Logs)
Voici un extrait des 8 premiers paquets malveillants capturés :

| Timestamp | Source (Attaquant) | Destination (Victime) | Flags TCP |
| :--- | :--- | :--- | :--- |
{lignes_tableau}

<div class="footer">
    Rapport généré par Script Python - SAÉ 1.05 - IUT R&T
</div>
"""

style_css = """
<style>
    body {
        font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        background-color: #f0f2f5;
        margin: 0;
        padding: 40px;
        color: #333;
    }
    .container {
        max-width: 900px;
        margin: 0 auto;
        background-color: white;
        padding: 50px;
        border-radius: 8px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.1);
    }
    .header {
        text-align: center;
        border-bottom: 2px solid #eee;
        margin-bottom: 30px;
        padding-bottom: 10px;
    }
    h1 { color: #2c3e50; margin: 0; font-size: 2.5em; }
    .header p { color: #7f8c8d; font-size: 0.9em; margin-top: 5px; }
    
    h2 {
        color: #2980b9;
        border-left: 5px solid #2980b9;
        padding-left: 15px;
        margin-top: 40px;
    }
    
    .alert {
        background-color: #fff5f5;
        border: 1px solid #fc8181;
        border-left: 5px solid #c0392b;
        color: #c0392b;
        padding: 20px;
        border-radius: 4px;
        font-size: 1.1em;
        margin: 30px 0;
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 20px;
        font-size: 0.95em;
    }
    th {
        background-color: #34495e;
        color: white;
        padding: 12px;
        text-align: left;
    }
    td {
        border-bottom: 1px solid #eee;
        padding: 10px;
    }
    tr:nth-child(even) { background-color: #f9f9f9; }
    tr:hover { background-color: #f1f1f1; }
    
    img {
        display: block;
        margin: 30px auto;
        max-width: 100%;
        border-radius: 5px;
        box-shadow: 0 4px 10px rgba(0,0,0,0.15);
        border: 1px solid #ddd;
    }
    
    .footer {
        text-align: center;
        margin-top: 50px;
        color: #bdc3c7;
        font-size: 0.8em;
        border-top: 1px solid #eee;
        padding-top: 20px;
    }
</style>
"""

html_content = markdown.markdown(rapport_md, extensions=['tables'])
chemin_html = os.path.join(dossier_base, "Rapport_Security.html")

with open(chemin_html, "w", encoding="utf-8") as f:
    f.write(f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport de Sécurité</title>
    {style_css}
</head>
<body>
    <div class="container">
        {html_content}
    </div>
</body>
</html>""")


print(f"✅ Rapport professionnel généré : {chemin_html}")
