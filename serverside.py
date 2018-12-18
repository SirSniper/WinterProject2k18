import socket, sys, json
from _thread import *
from Cryptodome.Util.number import *
from Cryptodome.Cipher import AES
from Cryptodome.Random import *

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

    # Generate and Initialization Vector for AES Encryption
    iv = Random.new().read(AES.block_size)
    conn.send(iv.encode())
    # Create encoding cipher
    conn.send(str.encode("BEGIN"))
    cipher = AES.new(long_to_bytes(shared), AES.MODE_CBC, iv)

    reply = "TEST REPLY "

    # Process input
    while True:
        data = conn.recv(blocksize)
        reply = reply + cipher.decrypt(data).decode()
        if not data:
            break
        conn.sendall(str.encode(cipher.encrypt(reply)))
        reply = "TEST REPLY "

    conn.close()
       

# Listen for incoming connections, generate a new thread
while True:
    conn, addr = s.accept()
    print("Connected to " + addr[0] + ": " + str(addr[1]))
    start_new_thread(threaded_client, (conn,))

s.close()