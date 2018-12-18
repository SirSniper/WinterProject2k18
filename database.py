import mysql
import hashlib, datetime, string, random, json, secrets

if(__name__ == "__main__"):
    with open("settings.cfg", "r", encoding="utf-8") as configFile:
        config = json.load(configFile).MySQLConfig
    
    host = config.host
    user = config.user
    password = config.password
    database = config.database

    mydb = mysql.connector.connect(
        host=host,
        user=user,
        passwd=password,
        database=database
    )

    mycursor = mydb.cursor()

def verifyUser(username, password):

    global mycursor
    # Check if user and pass combo exits
    mycursor.execute("SELECT * FROM Users WHERE username = %s or email = %s and password = SHA2(CONCAT(%s , salt), 512)", (username, username, password))
    user = mycursor.fetchone()
    # If the user exists, generate a unique token and insert it into the DB
    if(user):
        inserted = False
        # Continue trying to generate a new token
        while(not inserted):
            inserted = True
            time = str(datetime.datetime.now())
            token = secrets.token_hex(32)
            sql = "INSERT INTO tokens(userid, token, time) VALUES (%s, %s, %s)"
            val = (user[0], token, time)
            mycursor.execute(sql, val)
            try:
                mydb.commit()
            except MySQLdb.IntegrityError:
                inserted = False
    # If the user doesn't exist, return 0
    else:
        return False

    return {"token" : token,
            "time" : time,
            "userinfo" : user}

