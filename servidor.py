from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__)

@app.route('/firmar', methods=['POST'])
def firmar_documento():
    if 'documento' not in request.files:
        return jsonify({"error": "No se envió documento"}), 400
    
    archivo = request.files['documento']
    if archivo.filename == '':
        return jsonify({"error": "Nombre de archivo inválido"}), 400
    
    contenido = archivo.read()
    
    # Generar par de claves
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Firmar documento
    firma = private_key.sign(
        contenido,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return jsonify({
        "nombre_archivo": archivo.filename,
        "documento": base64.b64encode(contenido).decode('utf-8'),
        "firma": base64.b64encode(firma).decode('utf-8'),
        "public_key": public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8'),
        "mensaje": "Guarde la firma y la clave pública para futuras verificaciones"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)