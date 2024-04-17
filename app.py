import sqlite3
import json
import pandas as pd
from flask import Flask, render_template, request
import altair as alt
from hashlib import md5

cmi = Flask(__name__, template_folder='templates', static_folder='static')
cmi.config['SECRET_KEY'] = '1'


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@cmi.route("/")
def index():
    return render_template('index.html')


@cmi.route("/pages/")
def vuln_webs():
    amount = int(request.args.get("amount", default=10))
    with get_db_connection() as conn:
        df = unupgradedWEBS(amount, conn)
    chart = alt.Chart(df).mark_bar().encode(x="url", y="Politicas")
    return render_template('pages.html', df=df, graphJSON=chart.to_json())


@cmi.route("/users/")
def users():
    amount = int(request.args.get("amount", default=10))
    with get_db_connection() as conn:
        df = criticalUsers(amount, conn)
    chart = alt.Chart(df).mark_bar().encode(x="username", y="prob_clicados")
    return render_template('users.html', df=df, graphJSON=chart.to_json())


@cmi.route("/users/greater/")
def users_greater():
    amount = int(request.args.get("amount", default=10))
    with get_db_connection() as conn:
        df = criticalUsers(amount, conn)
    return render_template('users_greater.html', df=df)


@cmi.route("/users/less/")
def users_less():
    with get_db_connection() as conn:
        df = all_criticalUsers(conn)
    return render_template('users_less.html', df=df)


def criticalUsers(top: int, conn):
    with conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, emails_clicados, emails_phishing, contrasena FROM usuarios")
        rows = cursor.fetchall()

    df = pd.DataFrame(rows, columns=["username", "emails_clicados", "emails_phishing", "contrasena"])
    df["prob_clicados"] = df["emails_clicados"] / df["emails_phishing"].replace(0, 1)
    with open("weak_pass.txt", "r") as file:
        weak_passwords = set(file.read().split("\n"))
    df = df[df["contrasena"].isin(weak_passwords)]
    df = df.sort_values("prob_clicados", ascending=False).head(top)
    return df


def all_criticalUsers(conn):
    with conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, emails_clicados, emails_phishing, contrasena FROM usuarios")
        rows = cursor.fetchall()

    df = pd.DataFrame(rows, columns=["username", "emails_clicados", "emails_phishing", "contrasena"])
    df["prob_clicados"] = df["emails_clicados"] / df["emails_phishing"].replace(0, 1)
    with open("weak_pass.txt", "r") as file:
        weak_passwords = set(file.read().split("\n"))
    df = df[df["contrasena"].isin(weak_passwords)]
    
    # Ordenar por prob_clicados de mayor a menor
    df = df.sort_values("prob_clicados", ascending=False)
    return df


def unupgradedWEBS(top: int, conn):
    with conn:
        cursor = conn.cursor()
        cursor.execute("SELECT url, cookies, aviso, proteccion_de_datos, creacion FROM webs ORDER BY (cookies + aviso + proteccion_de_datos), creacion DESC LIMIT ?", (top,))
        rows = cursor.fetchall()
    
    df = pd.DataFrame(rows, columns=["url", "cookies", "aviso", "proteccion_de_datos", "creacion"])
    df["Politicas"] = df["cookies"] + df["aviso"] + df["proteccion_de_datos"]
    return df


if __name__ == '__main__':
    cmi.run()
