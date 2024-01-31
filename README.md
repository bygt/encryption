# Secure File Transfer using WebSockets

This project demonstrates a secure file transfer mechanism using WebSockets in Python. It provides options for symmetric encryption, digital signatures, and a combination of both for secure file transmission between a client and a server.

## Features

- **Symmetric Encryption**: Encrypts the file content using Fernet symmetric encryption before transmission.
- **Digital Signature**: Signs the file content using RSA digital signature for integrity verification.
- **Combined Encryption and Signature**: Encrypts the file content symmetrically and then signs it for both confidentiality and integrity.

## Requirements

- Python 3.x
- cryptography library (`pip install cryptography`)
- websockets library (`pip install websockets`)
- pycryptodome library (`pip install pycryptodome`)

## Usage

### Server Side

1. Run the `server.py` script.
2. Enter the file path of the file you want to send.
3. Choose the encryption/signature option:
   - `2`: Symmetric Encryption
   - `3`: Digital Signature
   - `4`: Encrypt and Sign
4. The server will listen for incoming connections.

### Client Side

1. Run the `client.py` script.
2. The client will connect to the server automatically.
3. The file will be received, decrypted, and/or verified based on the chosen option.

## Encryption Options

### Symmetric Encryption (Option 2)

- Encrypts the file content using Fernet symmetric encryption.
- Requires a pre-shared secret key.
- Provides confidentiality but not integrity.

### Digital Signature (Option 3)

- Signs the file content using RSA digital signature.
- Requires the server's public key for verification.
- Provides integrity but not confidentiality.

### Combined Encryption and Signature (Option 4)

- Encrypts the file content symmetrically and then signs it.
- Requires both a pre-shared secret key and the server's public key.
- Provides both confidentiality and integrity.

## Security Considerations

- Ensure that the pre-shared secret key is securely stored and shared only with authorized parties.
- Protect the server's private key used for digital signatures.
- Use strong encryption algorithms and key sizes.
- Consider additional security measures such as TLS for secure communication.

## Disclaimer

This project is for educational purposes only. Use it responsibly and ensure compliance with applicable laws and regulations.

