import json
from sklearn.linear_model import LinearRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
import numpy as np


with open('users_data_online_clasificado.json') as f:
    data = json.load(f)
usuarios = data['usuarios']
print(usuarios)
X = []
y = []
for usuario in np.asarray(usuarios):
    X.append([usuario[list(usuario.keys())[0]]['emails']['phishing'],
              usuario[list(usuario.keys())[0]]['emails']['cliclados']])
    y.append(usuario[list(usuario.keys())[0]]['critico'])

with open('users.json') as f:
    data_predecir = json.load(f)
predecir_X = []
for usuario in np.asarray(data_predecir['usuarios']):
    predecir_X.append([usuario[list(usuario.keys())[0]]['emails']['phishing'], usuario[list(usuario.keys())[0]]['emails']['cliclados']])

def linearRegression():
    print('Linear Regression')
    reg = LinearRegression().fit(X, y)
    print(reg.score(X, y))
    predecir_y = reg.predict((np.array(predecir_X)))
    print(predecir_y)
    return predecir_y

def decisionTree():
    print('Decision Tree')
    reg = DecisionTreeClassifier().fit(X, y)
    print(reg.score(X, y))
    predecir_y = reg.predict((np.array(predecir_X)))
    print(predecir_y)
    return predecir_y

def randomForest():
    print('Random Forest')
    reg = RandomForestClassifier().fit(X, y)
    print(reg.score(X, y))
    predecir_y = reg.predict((np.array(predecir_X)))
    print(predecir_y)
    return predecir_y

linearRegression()

decisionTree()

randomForest()