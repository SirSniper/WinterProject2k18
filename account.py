import database, datetime

class User:
    def __init__(self, username, password):
        foundUser = database.verifyUser(username, password)
        if(not foundUser):
            self.valid = False
        else:
            self.valid = True
            self.userid = foundUser.userinfo[0]
            self.username = foundUser.userinfo[1]
            self.token = foundUser.token
            self.timeout = datetime.datetime.strptime(foundUser.time) + datetime.timedelta(days=1)

    pass