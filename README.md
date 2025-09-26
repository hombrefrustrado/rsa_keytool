# rsa_keytool.py

Herramienta para generar pares de claves RSA, almacenarlas de forma segura y realizar operaciones de cifrado y descifrado. Soporta cifrado híbrido: utiliza AES-GCM para el mensaje y RSA-OAEP para proteger la clave simétrica.

## Requisitos

Instala la dependencia necesaria con:

```bash
pip install cryptography
```

## Uso

### Generar claves

Genera 10 pares de claves RSA de 2048 bits y guárdalas en la carpeta `keys/`:

```bash
python rsa_keytool.py generate --count 10 --bits 2048 --outdir keys/ --passphrase miaclave
```

Las claves se almacenan en dos subcarpetas dentro de `--outdir`:
- `public/`: claves públicas
- `private/`: claves privadas (cifradas con la passphrase)

### Encriptar un archivo

Cifra un archivo usando la clave pública con ID `0001`:

```bash
python rsa_keytool.py encrypt --pub keys/public/0001_pub.pem --infile mensaje.txt --outfile mensaje.enc
```

### Desencriptar un archivo

Descifra el archivo usando la clave privada correspondiente:

```bash
python rsa_keytool.py decrypt --priv keys/private/0001_priv.pem --passphrase miaclave --infile mensaje.enc --outfile mensaje.txt
```

## Buenas prácticas de seguridad

- **Nunca compartas las claves privadas.** Las claves públicas pueden compartirse, pero las privadas deben mantenerse seguras.
- **Usa passphrases robustas** para proteger las claves privadas.
- Considera utilizar un HSM o gestor de claves para entornos de producción.
- Implementa rotación y revocación de claves. El script mantiene un índice y huella digital (fingerprint) de las claves públicas.

---

rsa_keytool.py

Script para generar pares de claves RSA, almacenarlas, y realizar encriptación y desencriptación
(soporta cifrado híbrido: AES-GCM para el mensaje + RSA-OAEP para la clave simétrica).

Dependencias:
    pip install cryptography

Uso básico:
    # generar 10 pares de claves (2048 bits)
    python rsa_keytool.py generate --count 10 --bits 2048 --outdir keys/ --passphrase miaclave

    # encriptar (usa la clave pública del id 0001):
    python rsa_keytool.py encrypt --pub keys/public/0001_pub.pem --infile mensaje.txt --outfile mensaje.enc

    # desencriptar:
    python rsa_keytool.py decrypt --priv keys/private/0001_priv.pem --passphrase miaclave --infile mensaje.enc --outfile mensaje.txt

Este script crea dos subcarpetas dentro de --outdir: public/ y private/. Los ficheros privados se guardan cifrados con una passphrase.

IMPORTANTE DE SEGURIDAD:
 - Nunca compartas las claves privadas. Publicar claves PUBLICAS en Discord está bien; las privadas nunca.
 - Usa passphrases robustas para cifrar las claves privadas.
 - Considera usar HSM o un gestor de claves para producción.
 - Rotación de claves y revocación: mantiene un índice y huella (fingerprint) de las claves públicas.
