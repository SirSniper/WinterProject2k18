import mysql.connector
from mysql.connector import errorcode
from secrets import choice
import hashlib, datetime, string, random, json, os

ALPHABET = string.ascii_letters + string.digits

__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))

with open(os.path.join(__location__, 'settings.cfg'), "r", encoding="utf-8") as configFile:
    config = json.load(configFile)["MySQLConfig"]

host = config["host"]
user = config["user"]
password = config["password"]
database = config["database"]


try:
    mydb = mysql.connector.connect(
        host=host,
        user=user,
        passwd=password,
        database=database)
except mysql.connector.Error as err:
  if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
    print("Something is wrong with your user name or password")
  elif err.errno == errorcode.ER_BAD_DB_ERROR:
    print("Database does not exist")
  else:
    print(err)


mycursor = mydb.cursor()

def verifyUser(username, password):
    global mycursor
    # Check if user and pass combo exits
    mycursor.execute("SELECT * FROM Users WHERE username = %s or email = %s and passwordhash = SHA2(CONCAT(%s , salt), 512)", (username, username, password))
    user = mycursor.fetchone()
    # If the user exists, generate a unique token and insert it into the DB
    if(user):
        inserted = False
        # Continue trying to generate a new token
        while(not inserted):
            inserted = True
            time = str(datetime.datetime.now())
            token = ''.join(choice(ALPHABET) for i in range(32))
            sql = "INSERT INTO Tokens(userid, token, spawnTime) VALUES (%s, %s, %s)"
            val = (user[0], token, time)
            mycursor.execute(sql, val)
            sql = "DELETE FROM Tokens WHERE spawnTime > NOW()"
            mycursor.execute(sql)
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

def createUser(username, email, password):
    global mycursor
    salt = ''.join(random.choice(ALPHABET) for i in range(16))
    inserted = False
    # Check if the user already has an account
    mycursor.execute("SELECT * FROM Users WHERE username = %s or email = %s", (username, email))
    user = mycursor.fetchone()
    # Continue trying to generate a new userid
    if(not user):
        while(not inserted):
            inserted = True
            userid = ''.join(choice(ALPHABET) for i in range(64))
            mycursor.execute("INSERT INTO Users(userid, username, email, passwordhash, salt) VALUES (%s, %s, %s, SHA2(%s, 512), %s)", (userid, username, email, password + salt, salt))
            try:
                mydb.commit()
                return True
            except MySQLdb.IntegrityError:
                inserted = False
    else:
        return False
            
    



def verifyToken(username, tokenid):
    global mycursor
    # Check if user and pass combo exits
    mycursor.execute("DELETE FROM Tokens WHERE spawnTime > NOW()")
    try:
        mydb.commit()
    except MySQLdb.IntegrityError:
        return False
    mycursor.execute("SELECT * FROM Tokens WHERE username = %s or email = %s", (username, username))
    user = mycursor.fetchone()
    mycursor.execute("SELECT * FROM Tokens WHERE userid = %s and tokenid = %s", (user["userid"], tokenid))
    token = mycursor.fetchone()
    # If the user exists, generate a unique token and insert it into the DB
    if(token):
        # Continue trying to generate a new token
        return {"token" : tokenid,
            "time" : token["time"],
            "userinfo" : user}
            
    # If the user doesn't exist, return 0
    else:
        return False
    pass

def verifyGroup(groupID):
    global mycursor
    # Check if user and pass combo exits
    mycursor.execute("SELECT * FROM Groups WHERE groupid = %s", (groupID))
    group = mycursor.fetchone()
    if(group):
        mycursor.execute("SELECT userid FROM GroupMembers WHERE groupid = %s", (groupID))
        userids = []
        for user in mycursor.fetchall():
            userids.append(user)
        return userids
    # If the user doesn't exist, return 0
    else:
        return False
    pass

def getUserGroups(userID):
    global mycursor
    # Check if user and pass combo exits
    mycursor.execute("SELECT groupid FROM GroupMembers WHERE userid = %s", (userID))
    groups = mycursor.fetchall()
    if(groups):
        return groups
    else:
        return []
    pass