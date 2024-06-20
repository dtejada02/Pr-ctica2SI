import json
import pandas as pd
import joblib

model = joblib.load('model.pkl')

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

y_pred = model.predict(X)


cluster_labels = {0: 'No Crítico', 1: 'Crítico'}  # Cambia esto según los resultados observados
y_pred_mapped = [cluster_labels[label] for label in y_pred]

df['prediccion'] = y_pred_mapped

for index, row in df.iterrows():
    print(f"Usuario: {row['usuario']}, Predicción: {row['prediccion']}")
