## **1. Give examples of different integration protocols you have come across and give example scripts in python 3 on how to achieve each one.**

**REST API (HTTP/HTTPS)**
  ``` 
- REST Stands for Representational State Transfer. It is a software architectural style which uses a subset of HTTP. It is commonly used to create interactive applications that use Web services.
```
```
- REST API is a programming interfaces that is backed by the architectural style of REST.
   ```

#### An example of REST API server side implementation with Flask framework:

``` 
from flask import Flask, jsonify
app = Flask(__name__)

@app.route('/items')
def hello_world():
    return jsonify(
        [
            {
                "name":"item 1",
                "price":"40.00",
                "quantity:2
            },
             {
                "name":"item 2",
                "price":"50.00",
                "quantity:1
            }
        ]
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)

```
#### An example of Rest API Client side implementation with requests library:

```
response  = requests.get('http://localhost:8000/items')
print(response.status_code)

#get response content-type
response.headers['content-type']

#Get response encoding
response.encoding

#get response raw text
response.text

#get response json data.
response.json()
```

## **2. Give a walkthrough of how you will manage a data streaming application sending one million notifications every hour while giving examples of technologies and configurations you will use to manage load and asynchronous services.**

**Manage Load**

To manage load I would use load balancer like [Nginx](https://www.nginx.com/) or [Haproxy](http://www.haproxy.org/) to effectively distribute requests to the available servers capable of fullfilling them.
I would cache common static files and common network request on memory to speed up reading/retrieving of the data.
I would setup multiple workers for load balancers processes to improve system performance.
I would replicate Database servers to improve database query performance. 

**Asynchronous Services**

In asynchronous services I would used tools like [Celery](https://docs.celeryproject.org/en/stable/getting-started/introduction.html) to process background task.
I would use Redis for message queuing.
I would setup multiple celery workers workers to improve performance.
I would use websockets whenever possible to maintain client server connections so that client can receive update in real time.


## **2. Give examples of different encryption/hashing methods you have come across (one way and two way) and give example scripts in python 3 on how to achieve each one.**

1. **One Way**
 - Bcrypt - Is a password-hashing function designed by Niels Provos and David Mazières, based on the Blowfish cipher and presented at USENIX in 1999. Besides incorporating a salt to protect against rainbow table attacks, bcrypt is an adaptive function: over time, the iteration count can be increased to make it slower, so it remains resistant to brute-force search attacks even with increasing computation power. [Source Wikipedia](https://en.wikipedia.org/wiki/Bcrypt)

 ```
 # Hashing a password using bcrypt package

import bcrypt

password = b"a very strong password here"

hashed_password = bcrypt.hashpw(password,bcrypt.gensalt())  

isMatching = bcrypt.checkpw(password, hashed_password)

print(isMatching)

 ```


2. **Two Way**
- Symmetric Encryption - Is a type of encryption where only one key (a secret key) is used to both encrypt and decrypt electronic information. [Source](https://www.cryptomathic.com/news-events/blog/symmetric-key-encryption-why-where-and-how-its-used-in-banking#:~:text=Symmetric%20encryption%20is%20a%20type,used%20in%20the%20decryption%20process.)

*Encryption examples AES*
```
import hashlib
import math
import os
import secrets
from Crypto.Cipher import AES

text = b'A Clear Text'
password = secrets.token_bytes(20)
salt = os.urandom(16)
derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000,
                              dklen=48)
iv = derived[0:16]
key = derived[16:]

encrypted = salt + AES.new(key, AES.MODE_CFB, iv).encrypt(text)

...
```
*Decryption examples AES*
```
...
salt = encrypted[0:16]
derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000,
                              dklen= 48)
iv = derived[0:16]
key = derived[16:]
decrypted_text = AES.new(key, AES.MODE_CFB, iv).decrypt(encrypted[16:])
```

- Asymmetric Encryption - Is a type of encryption that uses two separates yet mathematically related keys to encrypt and decrypt data. The public key encrypts data while its corresponding private key decrypts it [Source](https://sectigostore.com/blog/what-is-asymmetric-encryption-how-does-it-work/#:~:text=Asymmetric%20encryption%20is%20a%20type,cryptography%2C%20and%20asymmetric%20key%20encryption.)

```
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

```
```
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
```
```
#Reading Encryption Keys
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
```

```
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
    with open('encrypted.txt', "ab") as f: f.write( base64.b64encode(encrypted))
```

```
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

print(read_data)
```