from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import constant_time
import os
import json
import argparse
import base64
import secrets


def generate_rsa_keypair(bits: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(private_key, passphrase: bytes = None):
    if passphrase:
        encryption_algo = serialization.BestAvailableEncryption(passphrase)
    else:
        encryption_algo = serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo,
    )
    return pem


def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem


def save_bytes(path: str, data: bytes, mode: int = 0o600):
    with open(path, 'wb') as f:
        f.write(data)
    try:
        os.chmod(path, mode)
    except Exception:
        pass


def fingerprint_public_key(public_pem: bytes) -> str:
    # SHA-256 fingerprint hex
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_pem)
    fp = digest.finalize().hex()
    return fp


# --- Hybrid encryption helpers -------------------------------------------------
# We will encrypt the plaintext with AES-GCM using a random 256-bit key.
# Then encrypt that AES key with RSA-OAEP (SHA-256).


def hybrid_encrypt(recipient_public, plaintext: bytes) -> bytes:
    # AES key
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # encrypt aes_key with RSA-OAEP
    enc_key = recipient_public.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # package: enc_key_len(4 bytes big-endian) | enc_key | nonce_len(1 byte) | nonce | ciphertext
    enc_key_len = len(enc_key).to_bytes(4, 'big')
    nonce_len = len(nonce).to_bytes(1, 'big')
    package = enc_key_len + enc_key + nonce_len + nonce + ciphertext
    return base64.b64encode(package)


def hybrid_decrypt(recipient_private, passphrase: bytes, package_b64: bytes) -> bytes:
    package = base64.b64decode(package_b64)
    # parse
    enc_key_len = int.from_bytes(package[0:4], 'big')
    idx = 4
    enc_key = package[idx:idx+enc_key_len]
    idx += enc_key_len
    nonce_len = package[idx]
    idx += 1
    nonce = package[idx:idx+nonce_len]
    idx += nonce_len
    ciphertext = package[idx:]

    # decrypt AES key with private RSA
    # if private key was serialized encrypted, caller should provide the loaded private_key object
    aes_key = recipient_private.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext

def sign_file(private_key, infile_path: str, outfile_path: str):
    # Leemos el mensaje
    message = open(infile_path, 'rb').read()

    # Firmamos usando PSS + SHA256
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Guardamos la firma en un archivo
    save_bytes(outfile_path, signature)
    print(f"File signed -> {outfile_path}")


def verify_file(public_key, infile_path: str, signature_path: str):
    message = open(infile_path, 'rb').read()
    signature = open(signature_path, 'rb').read()

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid")
    except Exception as e:
        print("Signature is INVALID")

# --- File helpers to load keys -------------------------------------------------


def load_public_key(pem_path: str):
    data = open(pem_path, 'rb').read()
    public_key = serialization.load_pem_public_key(data)
    return public_key


def load_private_key(pem_path: str, passphrase: bytes = None):
    data = open(pem_path, 'rb').read()
    private_key = serialization.load_pem_private_key(data, password=passphrase)
    return private_key


# --- CLI operations ------------------------------------------------------------


def cmd_generate(args):
    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)
    pubdir = os.path.join(outdir, 'public')
    privdir = os.path.join(outdir, 'private')
    os.makedirs(pubdir, exist_ok=True)
    os.makedirs(privdir, exist_ok=True)

    index = {}

    for i in range(1, args.count + 1):
        idstr = str(i).zfill(4)
        priv, pub = generate_rsa_keypair(bits=args.bits)
        pub_pem = serialize_public_key(pub)
        priv_pem = serialize_private_key(priv, passphrase=(args.passphrase.encode() if args.passphrase else None))

        pub_path = os.path.join(pubdir, f"{idstr}_pub.pem")
        priv_path = os.path.join(privdir, f"{idstr}_priv.pem")

        save_bytes(pub_path, pub_pem, mode=0o644)
        save_bytes(priv_path, priv_pem, mode=0o600)

        fp = fingerprint_public_key(pub_pem)
        index[idstr] = {"pub": pub_path, "priv": priv_path, "fingerprint_sha256": fp}
        print(f"Generated {idstr}  -> pub: {pub_path}  priv: {priv_path}  fp: {fp[:16]}...")

    index_path = os.path.join(outdir, 'index.json')
    with open(index_path, 'w') as f:
        json.dump(index, f, indent=2)
    print(f"Index written to {index_path}")


def cmd_encrypt(args):
    pub = load_public_key(args.pub)
    plaintext = open(args.infile, 'rb').read()
    package_b64 = hybrid_encrypt(pub, plaintext)
    save_bytes(args.outfile, package_b64)
    print(f"Encrypted -> {args.outfile} (base64 package)")


def cmd_decrypt(args):
    priv = load_private_key(args.priv, passphrase=(args.passphrase.encode() if args.passphrase else None))
    package_b64 = open(args.infile, 'rb').read()
    plaintext = hybrid_decrypt(priv, passphrase=(args.passphrase.encode() if args.passphrase else None), package_b64=package_b64)
    save_bytes(args.outfile, plaintext, mode=0o600)
    print(f"Decrypted -> {args.outfile}")

# --- Encriptar y desencriptar ---
def cmd_sign(args):
    priv = load_private_key(args.priv, passphrase=(args.passphrase.encode() if args.passphrase else None))
    sign_file(priv, args.infile, args.outfile)

def cmd_verify(args):
    pub = load_public_key(args.pub)
    verify_file(pub, args.infile, args.signature)

# --- firmar y verificar -----

def cmd_export_pub_bundle(args):
    pubdir = os.path.join(args.outdir, 'public')
    files = sorted([f for f in os.listdir(pubdir) if f.endswith('_pub.pem')])
    bundle = []
    for fn in files:
        path = os.path.join(pubdir, fn)
        pem = open(path, 'rb').read().decode()
        fp = fingerprint_public_key(pem.encode())
        bundle.append({'id': fn.split('_')[0], 'fingerprint_sha256': fp, 'pem': pem})
    with open(args.bundle, 'w') as f:
        json.dump(bundle, f, indent=2)
    print(f"Public key bundle written to {args.bundle}")


# --- Argument parser ----------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(description='RSA key generator + hybrid encrypt/decrypt tool')
    sub = p.add_subparsers(dest='cmd')

    gen = sub.add_parser('generate', help='Generar pares de claves RSA')
    gen.add_argument('--count', type=int, default=10)
    gen.add_argument('--bits', type=int, default=2048)
    gen.add_argument('--outdir', type=str, default='keys')
    gen.add_argument('--passphrase', type=str, default=None, help='passphrase para cifrar las claves privadas')
    gen.set_defaults(func=cmd_generate)

    enc = sub.add_parser('encrypt', help='Encriptar archivo para un destinatario usando su clave pública')
    enc.add_argument('--pub', type=str, required=True, help='ruta al PEM de la clave pública')
    enc.add_argument('--infile', type=str, required=True)
    enc.add_argument('--outfile', type=str, required=True)
    enc.set_defaults(func=cmd_encrypt)

    dec = sub.add_parser('decrypt', help='Desencriptar archivo con tu clave privada')
    dec.add_argument('--priv', type=str, required=True, help='ruta al PEM de la clave privada (puede estar cifrada)')
    dec.add_argument('--passphrase', type=str, default=None, help='passphrase si la clave privada está cifrada')
    dec.add_argument('--infile', type=str, required=True)
    dec.add_argument('--outfile', type=str, required=True)
    dec.set_defaults(func=cmd_decrypt)

    sign = sub.add_parser('sign', help='Firmar un archivo con tu clave privada')
    sign.add_argument('--priv', type=str, required=True, help='ruta al PEM de la clave privada')
    sign.add_argument('--passphrase', type=str, default=None, help='passphrase si la clave privada está cifrada')
    sign.add_argument('--infile', type=str, required=True)
    sign.add_argument('--outfile', type=str, required=True)
    sign.set_defaults(func=cmd_sign)

    verify = sub.add_parser('verify', help='Verificar la firma de un archivo')
    verify.add_argument('--pub', type=str, required=True, help='ruta al PEM de la clave pública')
    verify.add_argument('--infile', type=str, required=True)
    verify.add_argument('--signature', type=str, required=True)
    verify.set_defaults(func=cmd_verify)


    exp = sub.add_parser('export-bundle', help='Exportar todas las claves publicas a un JSON para publicar')
    exp.add_argument('--outdir', type=str, default='keys')
    exp.add_argument('--bundle', type=str, default='public_bundle.json')
    exp.set_defaults(func=cmd_export_pub_bundle)

    return p


if __name__ == '__main__':
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, 'func'):
        parser.print_help()
    else:
        args.func(args)
