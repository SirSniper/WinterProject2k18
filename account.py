import database, datetime

class User:
    def __init__(self, username, password):
        foundUser = database.verifyUser(username, password)
        if(not foundUser):
            self.valid = False
        else:
            self.valid = True
            self.userid = foundUser["userinfo"]["userid"]
            self.username = foundUser["username"]
            self.token = foundUser["token"]
            self.timeout = datetime.datetime.strptime(foundUser["time"]) + datetime.timedelta(days=1)
            self.groups = database.getUserGroups(self.userid)
        pass

    def getGroups(self):
        return self.groups

    pass