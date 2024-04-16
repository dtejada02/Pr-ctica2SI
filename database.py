import sqlite3
import json

con = sqlite3.connect('database.db')
cursorObj = con.cursor()

def create() -> None:
    """Creación de la base de datos. Si ya existía, la borra."""
    cursorObj.execute("DROP TABLE IF EXISTS usuarios")
    cursorObj.execute("DROP TABLE IF EXISTS fechas")
    cursorObj.execute("DROP TABLE IF EXISTS ips")

    cursorObj.execute("CREATE TABLE usuarios (username text, telefono integer, contrasena text, provincia text, "
                      "permisos bool, emails_total integer, emails_phishing integer, emails_clicados integer, "
                      "constraint PK_usuarios primary key (username)) ")
    cursorObj.execute(
        "CREATE TABLE fechas (username text, fecha text, constraint PK_fechas primary key (username,fecha), "
        "constraint FK_fechas_usuarios foreign key (username) references usuarios(username))")
    cursorObj.execute(
        "CREATE TABLE ips (username text, ip text, constraint PK_ips primary key (username,ip), constraint "
        "FK_ips_usuarios foreign key (username) references usuarios(username))")

    cursorObj.execute("DROP TABLE IF EXISTS webs")
    cursorObj.execute("CREATE TABLE webs (url text, cookies integer, aviso integer, proteccion_de_datos integer,"
                      "creacion integer, constraint PK_webs primary key (url))")
    con.commit()


def instantiate():
    """Lee el archivo users.json e inserta todos los valores en la base de datos.
    Si un valor es 'None', no se inserta nada.
    Esta función llama a create()"""
    create()
    with open("users.json", "r") as file:
        lines = json.load(file)

        for user in lines["usuarios"]:
            for username in user.keys():
                query = "INSERT INTO usuarios (username) VALUES (\'{}\')".format(username)
                cursorObj.execute(query)
                telefono = user[username]["telefono"]
                if telefono != 'None':
                    query = "UPDATE usuarios SET telefono = {} WHERE username = \'{}\'".format(telefono, username)
                    cursorObj.execute(query)
                query = "UPDATE usuarios SET contrasena = \'{}\' WHERE username = \'{}\'".format(
                    user[username]["contrasena"], username)
                cursorObj.execute(query)
                provincia = user[username]["provincia"]
                if provincia != 'None':
                    query = "UPDATE usuarios SET provincia = \'{}\' WHERE username = \'{}\'".format(provincia, username)
                    cursorObj.execute(query)
                permisos = user[username]["permisos"]
                query = "UPDATE usuarios SET permisos = {} WHERE username = \'{}\'".format(permisos, username)
                cursorObj.execute(query)
                emails_total = user[username]["emails"]["total"]
                query = "UPDATE usuarios SET emails_total = {} WHERE username = \'{}\'".format(emails_total, username)
                cursorObj.execute(query)
                emails_phishing = user[username]["emails"]["phishing"]
                query = "UPDATE usuarios SET emails_phishing = {} WHERE username = \'{}\'".format(emails_phishing,
                                                                                                  username)
                cursorObj.execute(query)
                emails_clicados = user[username]["emails"]["cliclados"]
                query = "UPDATE usuarios SET emails_clicados = {} WHERE username = \'{}\'".format(emails_clicados,
                                                                                                  username)
                cursorObj.execute(query)
                test = []
                for fecha in user[username]["fechas"]:
                    if fecha not in test:
                        query = "INSERT INTO fechas (username,fecha) VALUES (\'{}\',\'{}\')".format(username, fecha)
                        cursorObj.execute(query)
                        test.append(fecha)
                test = []
                if user[username]["ips"] == "None":
                    query = "INSERT INTO ips (username,ip) VALUES (\'{}\',Null)".format(username)
                    cursorObj.execute(query)
                else:
                    for ip in user[username]["ips"]:
                        if ip not in test:
                            query = "INSERT INTO ips (username,ip) VALUES (\'{}\',\'{}\')".format(username, ip)
                            cursorObj.execute(query)
                            test.append(ip)
    con.commit()

    with open("legal.json", "r") as file:
        lines = json.load(file)

        for web in lines["legal"]:
            for url in web.keys():
                # print(web[url]["cookies"])
                cookies = web[url]['cookies']
                aviso = web[url]['aviso']
                proteccion_de_datos = web[url]['proteccion_de_datos']
                creacion = web[url]['creacion']
                #print(web, cookies, aviso, proteccion_de_datos, creacion)
                #\'{}\',\'{}\'
                #web, cookies, aviso, proteccion_de_datos, creacion
                query = "INSERT INTO webs VALUES (\'{}\',\'{}\',\'{}\',\'{}\',\'{}\')".format(url, cookies, aviso,
                proteccion_de_datos, creacion)
                cursorObj.execute(query)
    con.commit()


instantiate()
con.close()
