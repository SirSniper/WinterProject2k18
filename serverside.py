import socket, sys, json, database, string, random
from threading import Thread
from base64 import b64encode, b64decode
from Cryptodome.Util.number import *
from Cryptodome.Cipher import AES
from Cryptodome.Random import *

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def padn(s, totalLen):
    return s + b"\0" * (totalLen - len(s) % totalLen)

with open("Chat Project\settings.cfg", "r", encoding="utf-8") as configFile:
    config = json.load(configFile)["ServerConfig"]

host = config["host"]
port = config["port"]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.bind((host, port))
except Exception as e:
    print("Error binding to port: " + e)
    sys.exit(0)

s.listen(1)

blocksize = config["blocksize"]

clients = []

class Client(Thread):
    def __init__(self, conn):
        Thread.__init__(self)
        self.conn = conn
        self.validated = False
        self.loginCount = 0
        self.connected = True
        pass

    

    requiredMessageFields = {
        "login" : ["username", "password", "token"],
        "file" : ["data", "filetype", "token"],
        "message" : ["data", "token"]
    }

    interchangableMessageFields = {
        "message" : ["groupid", "userid"]
    }

    def messageLogin(self):
        pass

    def sendFile(self):
        pass

    def message(self, messageContent):

        pass

    messageTypes = {
        "login" : messageLogin,
        "file" : sendFile,
        "message" : message
    }

    def getKey(self):
        # Generate a set of primes for AES encryption
        prime = getPrime(256)
        generator = getPrime(3)
        # Generate a private key
        private = getRandomInteger(256)
        # Generate a public key
        publicA = pow(generator, private, prime)
        # Send the prime
        self.conn.send(long_to_bytes(prime))
        print("Sent prime")
        # Send the generator
        self.conn.send(long_to_bytes(generator))
        print("Sent gen")
        # Send public key
        self.conn.send(long_to_bytes(publicA))
        print("Sent pub")
        # Wait for other public key
        publicB = bytes_to_long(self.conn.recv(blocksize))
        # Retrieve shared key from Diffie-Hellman
        shared = pow(publicB, private, prime)
        print("New shared key: " + str(shared))

        return shared

    def login(self):
        if(self.loginCount > 2):
            self.conn.close()
            self.connected = False
        else:
            loginAttempts = {"messageType" : "loginRequest", "Login" : self.loginCount}
            self.send(json.dumps(loginAttempts).encode("UTF-8"))
            try:
                values = json.loads(self.recieve())
            except Exception as e:
                print(e)
                return self.loginError()
            
            print(values)

            if("username" in values):
                if("password" in values):
                    # If there is a password field, then the program is attempting to login
                    self.user = database.verifyUser(values.get("username"), values.get("password"))
                    if(not self.user):
                        self.loginCount = self.loginCount + 1
                        return False
                    else:
                        self.send(json.dumps(self.user).encode("UTF-8"))
                        self.validated = True
                        return True
                elif("token" in values):
                    # Check to see if we have a user
                    if(self.user):
                        # If so compare and respond accordingly
                        if(self.user["token"] == values.get("token")):
                            self.validated = True
                            return True
                        else:
                            return self.loginError()
                    else:
                        # If not, check to see if the token is valid
                        self.user = database.verifyUser(values.get("username"), values.get("token"))
                        # If the token is valid, "sign" the user in
                        if(self.user):
                            print(self.user)
                            self.validated = True
                            return True
                    # If not, login error
                    return self.loginError()
                else:
                    return self.loginError()
            else:
                return self.loginError()
        return False

    def loginError(self):
        self.send(("Error On login attempt " + str(self.loginCount)).encode("UTF-8"))
        self.loginCount = self.loginCount + 1
        return False

    def genError(self, error):
        randomString = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))
        self.send((error + randomString).encode("UTF-8"))
        return False


    def send(self, data):
        header = b"header"
        cipher = AES.new(long_to_bytes(self.shared), AES.MODE_GCM)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # Create the key and value arrays
        json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        json_v = [ b64encode(x).decode('utf-8') for x in [cipher.nonce, header, ciphertext, tag] ]

        # Bind the key and value arrays together
        result = json.dumps(dict(zip(json_k, json_v)))
        print(data.decode("utf-8"))
        print(result)

        # Create a byte string to be sent
        resultStream = result.encode("UTF-8")

        # Convert the length of the incoming stream into a padded byte string
        streamLength = padn(str(len(resultStream)).encode("UTF-8"), 2048)
        self.conn.send(streamLength)
        self.conn.send(resultStream)

        pass

    def recieve(self):
        seenBytes = 0
        receivedData = b""
        data = self.conn.recv(blocksize)
        if not data:
            self.conn.close()
            self.connected = False
        try:
            streamLen = int(data.rstrip(b"\0").decode("UTF-8"))
        except Exception:
            try:
                while sock.recv(1024): pass
            except:
                pass
            self.send("Error Reading Last Message")
            return False

        while(not seenBytes == streamLen):
            # If we are near the end
            if(seenBytes + blocksize > streamLen):
                data = self.conn.recv(streamLen - seenBytes)
                receivedData = receivedData + data
                seenBytes = streamLen
            else:
                data = self.conn.recv(blocksize)
                receivedData = receivedData + data
                seenBytes = seenBytes + blocksize
        
        json_input = receivedData.decode("UTF-8")
        print(json_input)
        b64 = json.loads(json_input)
        json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        jv = {k : b64decode(b64[k]) for k in json_k}
        print(jv['nonce'])
        cipher = AES.new(long_to_bytes(self.shared), AES.MODE_GCM, nonce=jv['nonce'])
        cipher.update(jv['header'])
        plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
        print("The message was: " + plaintext.decode("UTF-8"))
        
        return plaintext.decode("UTF-8")

    def validateMessageType(self, messageType, message):
        if(not all (k in message for k in self.requiredMessageFields.get(messageType))):
            return False
        if(not len(set(self.interchangableMessageFields.get(messageType)) & set(message)) == 1):
            return False
        return True
        
    def run(self):
        self.shared = self.getKey()

        # Process input
        while self.connected:
            if(not self.validated):
                print("Logging in")
                self.login()
                continue

            message = self.recieve()
            if(message):
                try:
                    message = json.loads(message)
                except Exception:
                    self.genError("Error reading message")
                    continue

                # Check to see what type of message this is
                if("messageType" in message):
                    messageType = message["messageType"]
                    handle = self.messageTypes.get(messageType, message)
                else:
                    self.genError("Invalid message type header")
                    continue
                
                # Validate message type fields
                if(self.validateMessageType(messageType, message)):
                    # Perform message instruction 
                    handle()
                else:
                    self.genError("Invalid message field types")

                print(message)
            else:
                continue

        
        self.conn.close()

def threaded_client(conn):
    # Generate a set of primes for AES encryption
    prime = getPrime(256)
    generator = getPrime(3)
    # Generate a private key
    private = getRandomInteger(256)
    # Generate a public key
    publicA = pow(generator, private, prime)
    # Send the prime
    conn.send(long_to_bytes(prime))
    print("Sent prime")
    # Send the generator
    conn.send(long_to_bytes(generator))
    print("Sent gen")
    # Send public key
    conn.send(long_to_bytes(publicA))
    print("Sent pub")
    # Wait for other public key
    publicB = bytes_to_long(conn.recv(blocksize))
    # Retrieve shared key from Diffie-Hellman
    shared = pow(publicB, private, prime)
    print("New shared key: " + str(shared))

    # Create encoding cipher
    conn.send(str.encode("BEGIN"))

    reply = "TEST REPLY "

    header = b"header"
    receivedData = b""
    seenBytes = 0

    lenReceived = False

    # Process input
    while True:
        if(lenReceived):
            # If we are near the end
            if(seenBytes + blocksize > streamLen):
                data = conn.recv(streamLen - seenBytes)
                receivedData = receivedData + data
                seenBytes = streamLen
            else:
                data = conn.recv(blocksize)
                receivedData = receivedData + data
                seenBytes = seenBytes + blocksize

            if(seenBytes == streamLen):
                json_input = receivedData.decode("UTF-8")
                print(json_input)
                b64 = json.loads(json_input)
                json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
                jv = {k : b64decode(b64[k]) for k in json_k}
                print(jv['nonce'])
                cipher = AES.new(long_to_bytes(shared), AES.MODE_GCM, nonce=jv['nonce'])
                cipher.update(jv['header'])
                plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
                print("The message was: " + plaintext.decode("UTF-8"))
                
                lenReceived = False
                seenBytes = 0
                receivedData = b""
        else:
            data = conn.recv(blocksize)
            if not data:
                break
            streamLen = int(data.rstrip(b"\0").decode("UTF-8"))
            lenReceived = True
            
            
        reply = "TEST REPLY "

    conn.close()
       

connections = []
groups = {}

# Listen for incoming connections, generate a new thread
while True:
    conn, addr = s.accept()
    print("Connected to " + addr[0] + ": " + str(addr[1]))
    newClientConnection = Client(conn)
    newClientConnection.daemon = True
    newClientConnection.start()
    connections.append(newClientConnection)

s.close()