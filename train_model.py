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

with open('users.json', 'r') as file:
    data = json.load(file)

users = data['usuarios']

features_list = []

for user_dict in users:
    for username, info in user_dict.items():
        phishing_ratio = info['emails']['phishing'] / info['emails']['total'] if info['emails']['total'] > 0 else 0
        clicked_ratio = info['emails']['cliclados'] / info['emails']['total'] if info['emails']['total'] > 0 else 0

        dates = [datetime.strptime(date, "%d/%m/%Y") for date in info['fechas']]
        date_counts = Counter(date.strftime("%Y-%m-%d") for date in dates)
        avg_daily_connections = np.mean(list(date_counts.values())) if date_counts else 0
        ip_diversity = len(set(info['ips']))

        features_list.append({
            'username': username,
            'phishing_ratio': phishing_ratio,
            'clicked_ratio': clicked_ratio,
            'avg_daily_connections': avg_daily_connections,
            'ip_diversity': ip_diversity
        })

df_features = pd.DataFrame(features_list)

df_features['is_critical'] = ((df_features['phishing_ratio'] + df_features['clicked_ratio']) / 2 > 0.1).astype(int)

X = df_features[['phishing_ratio', 'clicked_ratio', 'avg_daily_connections', 'ip_diversity']]
y = df_features['is_critical']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

pipeline = make_pipeline(StandardScaler(), RandomForestClassifier(n_estimators=100, random_state=42))

pipeline.fit(X_train, y_train)

y_pred = pipeline.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred)

print(f"Accuracy: {accuracy}")
print("Classification Report:")
print(report)
joblib.dump(pipeline, 'modelo_usuario_critico.pkl')

