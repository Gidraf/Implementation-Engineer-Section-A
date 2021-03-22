# from zeep import Client

# wsdl = 'http://www.soapclient.com/xml/soapresponder.wsdl'
# client = Client(wsdl=wsdl)
# import pdb; pdb.set_trace()
# print(client.service.Method1('Zeep', 'is cool'))

# import re

# # Simplified version of a regex to match bcrypt passwords
# regular_expression = "^[$]2[abxy]?[$](?:0[4-9]|[12][0-9]|3[01])[$][./0-9a-zA-Z]{53}$"

# # A bcrypt password encoded with version "2y" and cost 12
# encoded_password = "$2a$12$PEmxrth.vjPDazPWQcLs6u9GRFLJvneUkcf/vcXn8L.bzaBUKeX4W"

# matches = re.search(regular_expression, encoded_password)

# if matches:
#   print("YES! We have a match!")
# else:
#   print("No match")

import hashlib
import math
import os
import secrets
from Crypto.Cipher import AES

# text = b'A Clear Text'
# password = secrets.token_bytes(20)
# salt = os.urandom(16)
# derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000,
#                               dklen=48)
# iv = derived[0:16]
# key = derived[16:]

# encrypted = salt + AES.new(key, AES.MODE_CFB, iv).encrypt(text)



# salt = encrypted[0:16]
# derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000,
#                               dklen= 48)
# iv = derived[0:16]
# key = derived[16:]
# decrypted_text = AES.new(key, AES.MODE_CFB, iv).decrypt(encrypted[16:])
# import pdb; pdb.set_trace()

# Generate Key
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

#Save Generated Key

# private key
serial_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open('private_key.pem', 'wb') as f: f.write(serial_private)
    
# public key
serial_pub = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open('public_key.pem', 'wb') as f: f.write(serial_pub)

#Reading Encryption Key
def read_private (filename = "private_key.pem"):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key
                  
""" Read Public Key """
def read_public (filename = "public_key.pem"):
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

"""Encryption with public key"""
data = [b'account balance', b'Ksh. 80,231,000']
public_key = read_public()
open('encrypted.txt', "wb").close() # clear file
for encode in data:
    encrypted = public_key.encrypt(
        encode,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # import pdb; pdb.set_trace()
    with open('encrypted.txt', "ab") as f: f.write( base64.b64encode(encrypted))


"""Decrypt"""
read_data = []
private_key = read_private()
with open('encrypted.txt', "rb") as f:
    for encrypted in f:
        read_data.append(
            private_key.decrypt(
                base64.b64decode(encrypted),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )))
