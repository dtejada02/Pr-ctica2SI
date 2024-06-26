import json
import pandas as pd
from sklearn.cluster import KMeans
import joblib

with open('users.json') as f:
    data = json.load(f)

usuarios_list = []
total_emails_list = []
phishing_emails_list = []
cliclados_emails_list = []
ips_count_list = []

for usuario in data["usuarios"]:
    for nombre_usuario, atributos in usuario.items():
        usuarios_list.append(nombre_usuario)
        total_emails_list.append(atributos["emails"]["total"])
        phishing_emails_list.append(atributos["emails"]["phishing"])
        cliclados_emails_list.append(atributos["emails"]["cliclados"])
        ips_count_list.append(len(atributos["ips"]))

df = pd.DataFrame({
    "usuario": usuarios_list,
    "total_emails": total_emails_list,
    "phishing_emails": phishing_emails_list,
    "cliclados_emails": cliclados_emails_list,
    "ips_count": ips_count_list
})

X = df[['total_emails', 'phishing_emails', 'cliclados_emails', 'ips_count']].copy()

kmeans = KMeans(n_clusters=2, random_state=42)
kmeans.fit(X)

joblib.dump(kmeans, 'model.pkl')