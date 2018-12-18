import socket
from Cryptodome.Util.number import *
from Cryptodome.Cipher import AES
from _thread import *

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

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
iv = (client_socket.recv(2048)).decode()
cipher = AES.new(long_to_bytes(shared), AES.MODE_CBC, iv)

def send_message(conn):
    data = input("SEND( TYPE q or Q to Quit):").encode('UTF-8')
    if (not data == 'Q' and not data == 'q'):
        print("Sending")
        print(data.hex())
        print(pad(data).hex())
        temp = cipher.encrypt(pad(data)) 
        newCipher = AES.new(long_to_bytes(shared), AES.MODE_CBC, iv)
        print(temp.hex())
        print("decrypted")
        print(newCipher.decrypt(temp).rstrip(b"\0").decode())

        conn.send((cipher.encrypt(data)))
    else:
        conn.send((cipher.encrypt(str.encode(data))))
        conn.close()

start_new_thread(send_message, (client_socket,))

while 1:
    data = client_socket.recv(2048)
    if(data.decode() == "BEGIN"):
        continue
    if (data == 'q' or data == 'Q'):
        client_socket.close()
        break
    else:
        print("RECIEVED:" + data.decode())
        print("Unencrypted: " + cipher.decrypt(data.decode()))
        if (data == 'Q' or data == 'q'):
            client_socket.send(data.encode())
            client_socket.close()
            break