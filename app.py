import sqlite3
import joblib
import numpy as np
import pandas as pd
import requests
from flask import Flask, render_template, request, make_response
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO
from algorithm_critical_user import linearRegressionUser
from algorithm_critical_user import decisionTreeUser
from algorithm_critical_user import randomForestUser


cmi = Flask(__name__, template_folder='templates', static_folder='static')
cmi.config['SECRET_KEY'] = '1'
model = joblib.load('model.pkl')


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
    return render_template('pages.html', df=df)


@cmi.route("/users/")
def users():
    amount = int(request.args.get("amount", default=10))
    with get_db_connection() as conn:
        df = criticalUsers(amount, conn)
    return render_template('users.html', df=df)


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
        cursor.execute(
            "SELECT url, cookies, aviso, proteccion_de_datos, creacion FROM webs ORDER BY (cookies + aviso + proteccion_de_datos), creacion DESC LIMIT ?",
            (top,))
        rows = cursor.fetchall()

    df = pd.DataFrame(rows, columns=["url", "cookies", "aviso", "proteccion_de_datos", "creacion"])
    df["Politicas"] = df["cookies"] + df["aviso"] + df["proteccion_de_datos"]
    return df



##### EJERCICIO 3 #####

@cmi.route("/vulnerabilities")
def vulnerabilitiesCVE():
    urlCVE = "https://cve.circl.lu/api/last"
    response = requests.get(urlCVE)
    if response.status_code == 200:
        data = response.json()
        vulnerabilities = []
        for cve in data[:10]:  # Obtener solo los primeros 10 elementos
            cve_id = cve["id"]
            description = cve["summary"]
            link = f"https://cve.circl.lu/cve/{cve_id}"
            date = cve["Published"]
            vulnerabilities.append({"CVE ID": cve_id, "Descripcion": description, "link": link, "Fecha de publicacion": date})

        return render_template('vulnerabilities.html', vulnerabilities=vulnerabilities)
    else:
        return f"Error al obtener las vulnerabilidades: {response.text}", 500

@cmi.route('/usuariosIA')
def usuarios_IA():
    return render_template('usuariosIA.html')
@cmi.route('/predict', methods=['POST'])
def predict():
    total_emails = float(request.form['total_emails'])
    phishing_emails = float(request.form['phishing_emails'])
    clicked_emails = float(request.form['clicked_emails'])
    ips_count = float(request.form['total_ip_addresses'])  # Nuevo campo para el total de direcciones IP

    input_data = np.array([total_emails, phishing_emails, clicked_emails, ips_count]).reshape(1, -1)

    prediction = model.predict(input_data)[0]

    return render_template('resultado_usuariosIA.html', resultado=prediction)



@cmi.route("/usuariosAlgorithm",  methods=["GET", "POST"])
def usuarios_algorit():
    if request.method == "POST":

        phishing = int(request.form['phishing'])
        clicados = int(request.form['clicados'])
        tipo = str(request.form['tipo'])
        if tipo == 'linearRegression':
            resultado = linearRegressionUser(phishing, clicados)
        elif tipo == 'randomForest':
            resultado = randomForestUser(phishing, clicados)
        elif tipo == 'decisionTree':
            resultado = decisionTreeUser(phishing, clicados)

        return render_template('resultado_usuariosIA.html', resultado=resultado)

    return render_template('users_algorithm.html')



@cmi.route('/descargar-reporte-usuarios-criticos/')
def descargar_reporte_usuarios_criticos():
    referer = request.headers.get('Referer')
    amount = request.args.get('amount', type=int, default=10)

    if referer and 'greater' in referer:
        with get_db_connection() as conn:
            df = criticalUsers(None, conn)
            df = df[df['prob_clicados'] > 0.5]
    elif referer and 'less' in referer:
        with get_db_connection() as conn:
            df = all_criticalUsers(conn)
            df = df[df['prob_clicados'] <= 0.5]
    else:
        with get_db_connection() as conn:
            df = criticalUsers(amount, conn)

    df = df.head(amount)

    buffer = BytesIO()

    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    p.drawString(100, height - 40, "Reporte de Usuarios Críticos")

    y_position = height - 60
    x_position = 50

    p.drawString(x_position, y_position, "Usuario")
    p.drawString(x_position + 200, y_position, "Emails Clicados")
    p.drawString(x_position + 300, y_position, "Emails Phishing")
    p.drawString(x_position + 400, y_position, "Probabilidad de Click")

    for index, row in df.iterrows():
        y_position -= 20
        p.drawString(x_position, y_position, row['username'])
        p.drawString(x_position + 200, y_position, str(row['emails_clicados']))
        p.drawString(x_position + 300, y_position, str(row['emails_phishing']))
        p.drawString(x_position + 400, y_position, str(row['prob_clicados']))

    p.showPage()
    p.save()
    buffer.seek(0)

    response = make_response(buffer.getvalue())
    buffer.close()
    response.headers['Content-Disposition'] = f'attachment; filename=reporte_usuarios_criticos_{amount}.pdf'
    response.mimetype = 'application/pdf'
    return response





if __name__ == '__main__':
    cmi.run()
