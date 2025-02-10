from flask import Flask, request, render_template
from Crypto.Cipher import AES
import base64
import os

app = Flask(__name__)

KEY = os.urandom(16)  # Generar clave AES aleatoria
IV = os.urandom(16)   # Generar vector de inicialización aleatorio

def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def encrypt(plain_text):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_text = cipher.encrypt(pad(plain_text).encode('utf-8'))
    return base64.b64encode(encrypted_text).decode('utf-8')

def decrypt(cipher_text):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted_text = cipher.decrypt(base64.b64decode(cipher_text)).decode('utf-8')
    return decrypted_text.strip()

@app.route('/', methods=['GET', 'POST'])
def index():
    encrypted_message = decrypted_message = ""
    if request.method == 'POST':
        message = request.form['message']
        if 'encrypt' in request.form:
            encrypted_message = encrypt(message)
        elif 'decrypt' in request.form:
            decrypted_message = decrypt(message)
    return render_template('index.html', encrypted=encrypted_message, decrypted=decrypted_message, key=base64.b64encode(KEY).decode('utf-8'))

if __name__ == '__main__':
    app.run(debug=True)
