import asyncio
import websockets

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
# import tkinter as tk
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import pickle

# --------------------start decryption
def symmetric_decrypt(ciphertext, key):

    cipher = Fernet(key)
    decrypted_data = cipher.decrypt(ciphertext)

    return decrypted_data.decode("utf-8")

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
# ---------------------end decryption

def generate_key_pair():
    key = RSA.generate(2048)
    print(key)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def verify_signature(public_key, message, signature):
    key = RSA.import_key(public_key)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

whitelist = [12345, 63184 ]



async def main():    

    # uri = "ws://31.223.96.100:12345"

    uri = "ws://127.0.0.1:12345"

    try:
        async with websockets.connect(uri) as websocket:
            file_content = await websocket.recv()
            print(f"Dosya alındı")
        operation = int(file_content[:1])
        ciphertext = file_content[1:]
        

        if operation == 1:
            decrypted_content = ciphertext.decode('utf-8')
            print("Received file", decrypted_content)

        elif operation == 2:
            
            key = generate_key()
            cipher = Fernet(key)
            decrypted_content = cipher.decrypt(ciphertext)
            print("Received and decrypted file:",decrypted_content.decode("utf-8"))

        elif operation == 3:        
            
            data = pickle.loads(ciphertext)
            public_key_A = data['public_key']
            message = data['message']
            signature = data['signature']

            if verify_signature(public_key_A, message, signature):
                print("ClientA'dan gelen mesaj doğrulandı:", message.decode('utf-8'))
                decrypted_content = message.decode('utf-8')
            else:
                print("ClientA'dan gelen mesaj doğrulanamadı.")

        elif operation == 4:
            data = pickle.loads(ciphertext)

            public_key_A = data['public_key']
            message = data['message']
            signature = data['signature']

            if verify_signature(public_key_A, message, signature):
                print("ClientA'dan gelen mesaj doğrulandı")
                ciphertext = message
                key = generate_key()
                decrypted_content = symmetric_decrypt(ciphertext, key)
                print(decrypted_content)          
            else:
                print("ClientA'dan gelen mesaj doğrulanamadı.")


    except websockets.exceptions.ConnectionClosedError as e:
        print(f"WebSocket connection closed unexpectedly: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise  # Hatanın tam olarak ne olduğunu görmek için bu satırı ekleyin




if __name__ == "__main__":
    asyncio.run(main())
    
