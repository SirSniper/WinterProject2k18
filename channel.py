import database, datetime

class Channel:
    def __init__(self, groupid):
        foundGroup = database.verifyGroup(groupid)
        if(not foundGroup):
            self.valid = False
        else:
            self.valid = True
            self.groupid = groupid
            self.users = foundGroup
        pass

    def validateUser(self, user):
        if(user in self.users):
            return True
        else:
            return False
    pass