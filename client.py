import socket, json
from Cryptodome.Util.number import *
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from Cryptodome.Random import *
from base64 import b64decode, b64encode
from _thread import *




def loginRequest(message):
    global client_socket
    send_message(client_socket, json.dumps({"username": "Nik", "password": "test123"}).encode("UTF-8"))

def messageReceived(message):
    print(message)

messageTypes = {
    "loginRequest" : loginRequest,
    "message" : messageReceived
}


def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def padn(s, totalLen):
    return s + b"\0" * (totalLen - len(s) % totalLen)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 5555))
prime = bytes_to_long(client_socket.recv(2048))
generator = bytes_to_long(client_socket.recv(2048))
publicA = bytes_to_long(client_socket.recv(2048))
private = getRandomInteger(256)
publicB = pow(generator, private, prime)
client_socket.send(long_to_bytes(publicB))
print("Sent pub")
shared = pow(publicA, private, prime)
print("New shared key: " + str(shared))

cipher = AES.new(long_to_bytes(shared), AES.MODE_GCM)

def send_message(conn, data):
    global cipher
    header = b"header"
    if (not data == 'Q' and not data == 'q'):
        cipher = AES.new(long_to_bytes(shared), AES.MODE_GCM)
        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # Create the key and value arrays
        json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
        json_v = [ b64encode(x).decode('utf-8') for x in [cipher.nonce, header, ciphertext, tag] ]

        # Bind the key and value arrays together
        result = json.dumps(dict(zip(json_k, json_v)))
        #print(result)

        # Create a byte string to be sent
        resultStream = result.encode("UTF-8")
        # Convert the length of the incoming stream into a padded byte string
        streamLength = padn(str(len(resultStream)).encode("UTF-8"), 2048)
        conn.send(streamLength)
        conn.send(resultStream)
    else:
        conn.close()

#start_new_thread(send_message, (client_socket,))

blocksize = 2048

def receive(conn):
    global shared
    seenBytes = 0
    receivedData = b""
    data = conn.recv(blocksize)
    if not data:
        conn.close()
        connected = False
    try:
        streamLen = int(data.rstrip(b"\0").decode("UTF-8"))
    except Exception:
        try:
            while sock.recv(1024): pass
        except:
            pass
        return False

    while(not seenBytes == streamLen):
        # If we are near the end
        if(seenBytes + blocksize > streamLen):
            data = conn.recv(streamLen - seenBytes)
            receivedData = receivedData + data
            seenBytes = streamLen
        else:
            data = conn.recv(blocksize)
            receivedData = receivedData + data
            seenBytes = seenBytes + blocksize
    
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
    return plaintext.decode("UTF-8")


while 1:
    data = receive(client_socket)
    if (data == 'q' or data == 'Q'):
        client_socket.close()
        break
    else:
        message = json.loads(data)
        if("messageType" in message):
            handle = messageTypes.get(message.get("messageType"))
            handle(message)
        else:
            continue
        if (data == 'Q' or data == 'q'):
            client_socket.send(data.encode())
            client_socket.close()
            break