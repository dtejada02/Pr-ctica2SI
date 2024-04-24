import json

import joblib
import pandas as pd
from collections import Counter
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import classification_report, accuracy_score
import numpy as np

# Carga y preparación de los datos
with open('users.json', 'r') as file:  # Asegúrate de que 'users.json' esté en la misma carpeta que tu script
    data = json.load(file)

# Extraemos los usuarios
users = data['usuarios']

# Lista para almacenar las características de cada usuario
features_list = []

# Paso 1: Definir las características (features) y Paso 2: Preparar los datos
for user_dict in users:
    for username, info in user_dict.items():
        phishing_ratio = info['emails']['phishing'] / info['emails']['total'] if info['emails']['total'] > 0 else 0
        clicked_ratio = info['emails']['cliclados'] / info['emails']['total'] if info['emails']['total'] > 0 else 0

        # Convertimos las fechas de strings a objetos datetime
        dates = [datetime.strptime(date, "%d/%m/%Y") for date in info['fechas']]
        # Contamos las conexiones por día
        date_counts = Counter(date.strftime("%Y-%m-%d") for date in dates)
        # Calculamos la frecuencia media de conexiones por día
        avg_daily_connections = np.mean(list(date_counts.values())) if date_counts else 0
        # Calculamos la diversidad de IPs como la cantidad de IPs únicas
        ip_diversity = len(set(info['ips']))

        # Añadimos las características a la lista
        features_list.append({
            'username': username,
            'phishing_ratio': phishing_ratio,
            'clicked_ratio': clicked_ratio,
            'avg_daily_connections': avg_daily_connections,
            'ip_diversity': ip_diversity
        })

# Convertimos la lista de características a un DataFrame
df_features = pd.DataFrame(features_list)

# Paso 3: Etiquetar los datos
# Aquí etiquetamos de forma arbitraria a los usuarios como críticos si tienen una alta proporción de clics en phishing
# En una situación real, esto debería hacerse con datos etiquetados por un experto
df_features['is_critical'] = ((df_features['phishing_ratio'] + df_features['clicked_ratio']) / 2 > 0.1).astype(int)

# Paso 4: Seleccionar un algoritmo y entrenar el modelo
X = df_features[['phishing_ratio', 'clicked_ratio', 'avg_daily_connections', 'ip_diversity']]
y = df_features['is_critical']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Creamos un pipeline para estandarizar los datos y luego entrenar un RandomForestClassifier
pipeline = make_pipeline(StandardScaler(), RandomForestClassifier(n_estimators=100, random_state=42))

# Entrenamos el modelo
pipeline.fit(X_train, y_train)

# Predecimos las etiquetas para el conjunto de prueba
y_pred = pipeline.predict(X_test)

# Evaluamos el modelo
accuracy = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred)

# Imprimimos la precisión y el reporte de clasificación
print(f"Accuracy: {accuracy}")
print("Classification Report:")
print(report)
joblib.dump(pipeline, 'modelo_usuario_critico.pkl')

