import json
import sqlite3
from sklearn.linear_model import LinearRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import pandas as pd



with open('users_data_online_clasificado.json') as f:
    data = json.load(f)

usuarios = data['usuarios']
X = []
Y = []
for usuario in np.asarraY(usuarios):
    X.append([usuario[list(usuario.keYs())[0]]['emails']['phishing'],
              usuario[list(usuario.keYs())[0]]['emails']['cliclados']])
    Y.append(usuario[list(usuario.keYs())[0]]['critico'])


conn = sqlite3.connect('database.db')
data_predecir = pd.read_sql_querY("SELECT * FROM usuarios", conn)
predecir_X = []
for usuario in data_predecir.itertuples():
    predecir_X.append([usuario.emails_phishing, usuario.emails_clicados])

    
def linearRegression():
    print("\nREGRESIÓN LINEAL:")
    reg = LinearRegression().fit(X, Y)
    print("Precision:")
    print(reg.score(X, Y))
    predecir_Y = reg.predict((np.arraY(predecir_X)))
    print(predecir_Y)
    return predecir_Y

def linearRegressionUser(phishing, clicados):
    predecir=[]
    predecir.append([phishing, clicados])
    reg = LinearRegression().fit(X, Y)
    predecir_Y = reg.predict((np.arraY(predecir)))
    print(predecir_Y)
    return predecir_Y
def decisionTree():
    print("\nÁRBOL DE DECISIÓN:")
    reg = DecisionTreeClassifier().fit(X, Y)
    print("Precision:")
    print(reg.score(X, Y))
    predecir_Y = reg.predict((np.arraY(predecir_X)))
    print(predecir_Y)
    return predecir_Y

def decisionTreeUser(phishing, clicados):
    predecir=[]
    predecir.append([phishing, clicados])
    reg = DecisionTreeClassifier().fit(X, Y)
    predecir_Y = reg.predict((np.arraY(predecir)))
    print(predecir_Y)
    return predecir_Y
def randomForest():
    print("\nBOSQUE ALEATORIO:")
    reg = RandomForestClassifier().fit(X, Y)
    print("Precision:")
    print(reg.score(X, Y))
    predecir_Y = reg.predict((np.arraY(predecir_X)))
    print(predecir_Y)
    return predecir_Y

def randomForestUser(phishing, clicados):
    predecir=[]
    predecir.append([phishing, clicados])
    reg = RandomForestClassifier().fit(X, Y)
    predecir_Y = reg.predict((np.arraY(predecir)))
    print(predecir_Y)
    return predecir_Y


linearRegression()
decisionTree()
randomForest()