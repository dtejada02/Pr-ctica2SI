import json
import sqlite3
from sklearn.linear_model import LinearRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import pandas as pd

conn = sqlite3.connect('database.db')
data_predecir = pd.read_sql_query("SELECT * FROM usuarios", conn)

with open('users_data_online_clasificado.json') as f:
    data = json.load(f)

usuarios = data['usuarios']
X = []
y = []
for usuario in np.asarray(usuarios):
    X.append([usuario[list(usuario.keys())[0]]['emails']['phishing'],
              usuario[list(usuario.keys())[0]]['emails']['cliclados']])
    y.append(usuario[list(usuario.keys())[0]]['critico'])

predecir_X = []
for usuario in data_predecir.itertuples():
    predecir_X.append([usuario.emails_phishing, usuario.emails_clicados])
def linearRegression():
    print("\nREGRESIÓN LINEAL:")
    reg = LinearRegression().fit(X, y)
    print("Precision:")
    print(reg.score(X, y))
    predecir_y = reg.predict((np.array(predecir_X)))
    print(predecir_y)
    return predecir_y

def linearRegressionUser(phishing, clicados):
    predecir=[]
    predecir.append([phishing, clicados])
    reg = LinearRegression().fit(X, y)
    predecir_y = reg.predict((np.array(predecir)))
    print(predecir_y)
    return predecir_y
def decisionTree():
    print("\nÁRBOL DE DECISIÓN:")
    reg = DecisionTreeClassifier().fit(X, y)
    print("Precision:")
    print(reg.score(X, y))
    predecir_y = reg.predict((np.array(predecir_X)))
    print(predecir_y)
    return predecir_y

def decisionTreeUser(phishing, clicados):
    predecir=[]
    predecir.append([phishing, clicados])
    reg = DecisionTreeClassifier().fit(X, y)
    predecir_y = reg.predict((np.array(predecir)))
    print(predecir_y)
    return predecir_y
def randomForest():
    print("\nBOSQUE ALEATORIO:")
    reg = RandomForestClassifier().fit(X, y)
    print("Precision:")
    print(reg.score(X, y))
    predecir_y = reg.predict((np.array(predecir_X)))
    print(predecir_y)
    return predecir_y

def randomForestUser(phishing, clicados):
    predecir=[]
    predecir.append([phishing, clicados])
    reg = RandomForestClassifier().fit(X, y)
    predecir_y = reg.predict((np.array(predecir)))
    print(predecir_y)
    return predecir_y


linearRegression()
decisionTree()
randomForest()