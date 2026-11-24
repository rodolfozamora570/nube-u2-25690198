import os, boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

kms = boto3.client('kms')
LLAVE_MAESTRA = "alias/clasificaia"

def cifrar(datos: bytes) -> dict:
    dk = kms.generate_dat_key(KeyId=LLAVE_MAESTRA, KeySpec='AES_256')
    nonce = os.urandom(12)
    cifrado = AESGCM(dk['Plaintext']).encrypt(nonce, datos, None)
    del dk ["Plaintext"]
    return {"clave_cifrada": dk['CiphertextBlob'], "nonce": nonce, "datos": cifrado}

def descifrar(sobre: dict) -> bytes:
    llave = kms.decrypt(CiphertextBlob=sobre['clave_cifrada'])['Plaintext']
    return AESGCM(llave).decrypt(sobre['nonce'], sobre['datos'], None)

sobre = cifrar(open("pacientes.csv", "rb").read())
assert descifrar(sobre) == open("pacientes.csv", "rb").read()