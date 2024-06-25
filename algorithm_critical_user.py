import json
import sqlite3

from emit import graphviz
from sklearn.linear_model import LinearRegression
from sklearn.tree import DecisionTreeClassifier, export_graphviz
from sklearn.ensemble import RandomForestClassifier
from sklearn import tree
import numpy as np
import pandas as pd
import graphviz



with open('users_data_online_clasificado.json') as f:
    data = json.load(f)

usuarios = data['usuarios']
X = []
Y = []
for usuario in np.asarray(usuarios):
    X.append([usuario[list(usuario.keys())[0]]['emails']['phishing'],
              usuario[list(usuario.keys())[0]]['emails']['cliclados']])
    Y.append(usuario[list(usuario.keys())[0]]['critico'])


conn = sqlite3.connect('database.db')
data_predecir = pd.read_sql_query("SELECT * FROM usuarios", conn)
predecir_X = []
for usuario in data_predecir.itertuples():
    predecir_X.append([usuario.emails_phishing, usuario.emails_clicados])

    
def linearRegression():
    print("\nREGRESIÓN LINEAL:")
    reg = LinearRegression().fit(X, Y)
    print("Precision:")
    print(reg.score(X, Y))
    predecir_Y = reg.predict((np.array(predecir_X)))
    print(predecir_Y)
    return predecir_Y

def linearRegressionUser(phishing, clicados):
    predecir=[]
    predecir.append([phishing, clicados])
    reg = LinearRegression().fit(X, Y)
    predecir_Y = reg.predict((np.array(predecir)))
    print(predecir_Y)
    return predecir_Y
def decisionTree():
    print("\nÁRBOL DE DECISIÓN:")
    reg = DecisionTreeClassifier().fit(X, Y)
    print("Precision:")
    print(reg.score(X, Y))
    predecir_Y = reg.predict((np.array(predecir_X)))
    print(predecir_Y)
    dot_data = tree.export_graphviz(reg, out_file=None,feature_names=['emails_phishing', 'emails_clicados'],class_names=['no_crítico', 'crítico'],filled=True, rounded=True,special_characters=True)
    graph = graphviz.Source(dot_data)
    graph.render("decision_tree")
    return predecir_Y

def decisionTreeUser(phishing, clicados):
    predecir=[]
    predecir.append([phishing, clicados])
    reg = DecisionTreeClassifier().fit(X, Y)
    predecir_Y = reg.predict((np.array(predecir)))
    print(predecir_Y)
    return predecir_Y
def randomForest():
    print("\nBOSQUE ALEATORIO:")
    reg = RandomForestClassifier().fit(X, Y)
    print("Precision:")
    print(reg.score(X, Y))
    predecir_Y = reg.predict((np.array(predecir_X)))
    print(predecir_Y)
    forest = RandomForestClassifier().fit(X, Y)
    estimator = forest.estimators_[0]
    dot_data = tree.export_graphviz(estimator, out_file=None,feature_names=['emails_phishing', 'emails_clicados'],class_names=['no_crítico', 'crítico'],filled=True, rounded=True,special_characters=True)
    graph = graphviz.Source(dot_data)
    graph.render("random_forest")
    return predecir_Y

def randomForestUser(phishing, clicados):
    predecir=[]
    predecir.append([phishing, clicados])
    reg = RandomForestClassifier().fit(X, Y)
    predecir_Y = reg.predict((np.array(predecir)))
    print(predecir_Y)
    return predecir_Y


#linearRegression()
decisionTree()
randomForest()