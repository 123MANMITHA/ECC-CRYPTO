from flask import Flask, request, jsonify, render_template
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
import base64

app = Flask(__name__)

# Generate ECC key pairs for sender and recipient
private_key_sender, public_key_sender = ec.generate_private_key(ec.SECP256R1(), default_backend()), None
private_key_recipient, public_key_recipient = ec.generate_private_key(ec.SECP256R1(), default_backend()), None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    global private_key_sender, public_key_sender, private_key_recipient, public_key_recipient
    private_key_sender = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key_sender = private_key_sender.public_key()
    private_key_recipient = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key_recipient = private_key_recipient.public_key()
    return jsonify({
        "public_key_sender": public_key_sender.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        "public_key_recipient": public_key_recipient.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    })

@app.route('/encrypt', methods=['POST'])
def encrypt_email():
    data = request.get_json()
    email_content = data['email_content'].encode()

    shared_key = private_key_sender.exchange(ec.ECDH(), public_key_recipient)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    aesgcm = AESGCM(derived_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, email_content, None)

    return jsonify({
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    })

@app.route('/decrypt', methods=['POST'])
def decrypt_email():
    data = request.get_json()
    nonce = base64.b64decode(data['nonce'])
    ciphertext = base64.b64decode(data['ciphertext'])

    shared_key = private_key_recipient.exchange(ec.ECDH(), public_key_sender)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    aesgcm = AESGCM(derived_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return jsonify({"email_content": plaintext.decode()})

@app.route('/sign', methods=['POST'])
def sign_email():
    data = request.get_json()
    email_content = data['email_content'].encode()

    signature = private_key_sender.sign(
        email_content,
        ec.ECDSA(hashes.SHA256())
    )

    return jsonify({"signature": base64.b64encode(signature).decode()})

@app.route('/verify', methods=['POST'])
def verify_signature():
    data = request.get_json()
    email_content = data['email_content'].encode()
    signature = base64.b64decode(data['signature'])

    try:
        public_key_sender.verify(
            signature,
            email_content,
            ec.ECDSA(hashes.SHA256())
        )
        return jsonify({"valid": True})
    except Exception as e:
        return jsonify({"valid": False})

if __name__ == '__main__':
    app.run(debug=True)
