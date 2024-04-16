import sqlite3
import json
import pandas as pd
from flask import Flask, render_template, request, redirect
import altair as alt
import requests  
from hashlib import md5

con = sqlite3.connect('.\database.db')
cursorObj = con.cursor()

cmi = Flask(__name__, template_folder='templates', static_folder='static')
cmi.config['SECRET_KEY'] = '1'

@cmi.route("/")
def index():
    return render_template('index.html')

@cmi.route("/pages/")
def vuln_webs():
    args = request.args
    amount = args.get("amount", default=5)
    df = unupgradedWEBS(int(amount))
    chart = alt.Chart(df).mark_bar().encode(x="url", y="Politicas")

    graphJSON=chart.to_json()
    print(graphJSON)

    return render_template('pages.html', graphJSON=chart.to_json())

@cmi.route("/users/")
def users():
    args = request.args
    amount = args.get("amount", default=10)
    df = criticalUsers(int(amount))
    chart = alt.Chart(df).mark_bar().encode(x="username", y="prob_click")
    df2 = phisingCLICKS(bool(args.get("greater", default=False)))

    graphJSON=chart.to_json()
    print(graphJSON)

    return render_template('users.html', graphJSON=chart.to_json(), click=df2.to_html())


def phisingCLICKS(greater: bool):
    if greater:
        return pd.read_sql_query(
            "SELECT username,telefono,provincia,emails_total,emails_phishing,emails_clicados FROM usuarios where emails_clicados>usuarios.emails_phishing/2",
            con)
    else:
        return pd.read_sql_query(
            "SELECT username,telefono,provincia,emails_total,emails_phishing,emails_clicados FROM usuarios where emails_clicados<=usuarios.emails_phishing/2",
            con)

def criticalUsers(top: int):
    df = pd.read_sql_query("SELECT username, emails_clicados, emails_phishing, contrasena FROM usuarios", con)
    for index, row in df.iterrows():
        if row["emails_phishing"] != 0:
            df._set_value(index, "prob_click", row["emails_clicados"] / row["emails_phishing"])
        else:
            df._set_value(index, "prob_click", 0)
    df = df.sort_values("prob_click", ascending=False)

    with open("weak_pass.txt", "r") as file:
        weak_passwords = set(file.read().split("\n"))
    df = df[df["contrasena"].isin(weak_passwords)]
    df = df.head(top)
    return df


def unupgradedWEBS(top: int):
    # Qué se entiende por web vulnerable?
    df = pd.read_sql_query("SELECT url, cookies, aviso, proteccion_de_datos FROM webs ORDER BY url", con)
    df["Politicas"] = df["cookies"] + df["aviso"] + df["proteccion_de_datos"]
    df = df.sort_values("Politicas").head(top)
    # df = df.replace({0:1, 1:0})
    return df




if __name__ == '__main__':
    cmi.run()




