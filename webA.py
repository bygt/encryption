
import websockets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.fernet import Fernet
import pickle
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import asyncio



# --------------------start encryption
def symmetric_encrypt(data, key):
    # Fernet anahtarı oluştur
    cipher = Fernet(key)
    ciphertext = cipher.encrypt(data.encode())

    return ciphertext


def generate_key():
    password = b"secret_password"
    salt = b"salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key
# ---------------------end encryption


def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_message(private_key, message):
    key = RSA.import_key(private_key)
    h = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(h)
    return signature

async def send_file(websocket, choice, file_path):

    choice = int(choice)
    with open(file_path, 'rb') as file:
        file_content = file.read()

        print(file_content)
        


        if choice == 2:

            key = generate_key()
            cipher = Fernet(key)
            data = file_content.decode("utf-8")
            encrypted_content = cipher.encrypt(data.encode())
            print(encrypted_content)
            await websocket.send(b'2' + encrypted_content)

        elif choice == 3:

            private_key_A, public_key_A = generate_key_pair()
            signature = sign_message(private_key_A, file_content)
            data = {
                'public_key': public_key_A,
                'message': file_content,
                'signature': signature
            }
            await websocket.send(b'3' + pickle.dumps(data))

            
        elif choice == 4:
            # symmetric encryption
            key = generate_key()
            cipher = Fernet(key)
            data = file_content.decode("utf-8")
            encrypted_content = cipher.encrypt(data.encode())

            # digital signature
            private_key_A, public_key_A = generate_key_pair()
            signature = sign_message(private_key_A, encrypted_content)
            data = {
                'public_key': public_key_A,
                'message': encrypted_content,
                'signature': signature
            }
            # send encrypted content and digital signature to client B
            combined_data = b'4' + pickle.dumps(data)
            await websocket.sendall(combined_data)
        else:
            print("Invalid choice.")

whitelist = ['127.0.0.1' ]

async def main(websocket, path):

    client_ip = websocket.remote_address[0]
    if client_ip not in whitelist:
        print("Connection attempt from non-whitelisted IP address: ", client_ip)
        return
    else:
        print("Connection established from: ", client_ip)

    file_path= input("Enter file path: ")
    choice = input("\n2- Smymetric Encryption\n3- Digital Signature\n4- Encrypt and Sign\nEnter your choice: ")
    otion = int(choice)
    await send_file(websocket, choice, file_path)
    # asyncio.run(send_choice(choice, file_path))

 
start_server = websockets.serve(main, '0.0.0.0', 12345)
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()


if __name__ == "__main__":
    asyncio.run(main())
    
