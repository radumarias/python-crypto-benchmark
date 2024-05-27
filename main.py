import errno
import datetime
import os
import io

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.ciphers.algorithms import CAST5
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box
import pyAesCrypt
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Cipher import Salsa20
from Crypto.Cipher import ChaCha20
from struct import pack
from Crypto.Random import get_random_bytes

def read_file_in_chunks(file_path, buf, chunk_size=16 * 1024):
    with open(file_path, "rb") as file:
        while True:
            len = file.readinto(buf)
            if len == 0:
                break
            yield len

def silentremove(filename):
    try:
        os.remove(filename)
    except OSError as e:  # this would be "except OSError, e:" before Python 2.6
        if e.errno != errno.ENOENT:  # errno.ENOENT = no such file or directory
            raise  # re-raise exception if a different error occurred


def cryptography_fernet(path_in):
    print("cryptography.fernet aes")

    # key generation
    key = Fernet.generate_key()

    # using the generated key
    fernet = Fernet(key)

    a = datetime.datetime.now()

    # opening the original file to encrypt
    with open(
        path_in,
        "rb",
    ) as file:
        original = file.read()

    # encrypting the file
    ciphertext = fernet.encrypt(original)

    # opening the file in write mode and
    # writing the ciphertext data
    silentremove("/tmp/test.enc")
    with open("/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/tmp/test.enc", "rb") as enc_file:
        ciphertext = enc_file.read()

    # decrypting the file
    plaintext = fernet.decrypt(ciphertext)

    # opening the file in write mode and
    # writing the plaintext data
    silentremove("/tmp/test.dec")
    with open("/tmp/test.dec", "wb") as dec_file:
        dec_file.write(plaintext)

    b = datetime.datetime.now()
    delta = b - a
    print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


def cryptography_chacha20poly1305(path_in):
    print("cryptography.hazmat chacha20poly1305")

    aad = b"authenticated but unciphertext data"
    # key generation
    key = ChaCha20Poly1305.generate_key()

    # using the generated key
    chacha = ChaCha20Poly1305(key)

    nonce = os.urandom(12)

    deltas = []
    for _ in range(42):
        a = datetime.datetime.now()
        
        silentremove("/tmp/test.enc")
        buf = bytearray(128 * 1024)
        with open("/tmp/test.enc", "wb") as file_out:
            buffered_writer = io.BufferedWriter(file_out)
            for read in read_file_in_chunks(path_in, buf, chunk_size=buf.__len__()):
                ciphertext = chacha.encrypt(nonce, buf[:read], aad)
                buffered_writer.write(ciphertext[:read])
            buffered_writer.flush()
                
        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())
    average = sum(deltas, 0) / len(deltas)
    print("encrypt %2d MB/s" % (895 / average))

    # a = datetime.datetime.now()

    # # opening the ciphertext file
    # with open("/tmp/test.enc", "rb") as enc_file:
    #     ciphertext = enc_file.read()

    # # decrypting the file
    # plaintext = chacha.decrypt(nonce, ciphertext, aad)

    # # opening the file in write mode and
    # # writing the plaintext data
    # silentremove("/tmp/test.dec")
    # with open("/tmp/test.dec", "wb") as dec_file:
    #     dec_file.write(plaintext)

    # b = datetime.datetime.now()
    # delta = b - a
    # print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


def cryptography_aesgcm(path_in):
    print("cryptography.hazmat aesgcm")

    aad = b"authenticated but unciphertext data"
    # key generation
    key = AESGCM.generate_key(256)

    # using the generated key
    aesgcm = AESGCM(key)

    nonce = os.urandom(12)

    deltas = []
    for _ in range(42):
        a = datetime.datetime.now()


        silentremove("/tmp/test.enc")
        buf = bytearray(128 * 1024)
        with open("/tmp/test.enc", "wb") as file_out:
            buffered_writer = io.BufferedWriter(file_out)
            for read in read_file_in_chunks(path_in, buf, chunk_size=buf.__len__()):
                ciphertext = aesgcm.encrypt(nonce, buf[:read], aad)
                buffered_writer.write(ciphertext[:read])
            buffered_writer.flush()

        b = datetime.datetime.now()
        delta = b - a
        # print("encrypt %2d MB/s" % (895 / delta.total_seconds()))
        deltas.append(delta.total_seconds())
    average = sum(deltas, 0) / len(deltas)
    print("encrypt %2d MB/s" % (895 / average))

    # a = datetime.datetime.now()

    # # opening the ciphertext file
    # with open("/tmp/test.enc", "rb") as enc_file:
    #     ciphertext = enc_file.read()

    # # decrypting the file
    # plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

    # # opening the file in write mode and
    # # writing the plaintext data
    # silentremove("/tmp/test.dec")
    # with open("/tmp/test.dec", "wb") as dec_file:
    #     dec_file.write(plaintext)

    # b = datetime.datetime.now()
    # delta = b - a
    # print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


def cryptography_cast5(path_in):
    print("cryptography.hazmat cast5")

    # key generation
    key = os.urandom(16)
    iv = os.urandom(8)

    algorithm = CAST5(key)
    cipher = Cipher(algorithm, modes.CBC(iv))
    encryptor = cipher.encryptor()

    a = datetime.datetime.now()

    # opening the original file to encrypt
    with open(
        path_in,
        "rb",
    ) as file:
        original = file.read()

    # encrypting the file
    ciphertext = encryptor.update(original)

    # opening the file in write mode and
    # writing the ciphertext data
    silentremove("/tmp/test.enc")
    with open("/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/tmp/test.enc", "rb") as enc_file:
        ciphertext = enc_file.read()

    # decrypting the file
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)

    # opening the file in write mode and
    # writing the plaintext data
    silentremove("/tmp/test.dec")
    with open("/tmp/test.dec", "wb") as dec_file:
        dec_file.write(plaintext)

    b = datetime.datetime.now()
    delta = b - a
    print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


def cryptography_aesgcmsiv(path_in):
    print("cryptography.hazmat AESGCMSIV")

    aad = b"authenticated but unciphertext data"
    # key generation
    key = AESGCMSIV.generate_key(256)

    # using the generated key
    aesgcm = AESGCMSIV(key)

    nonce = os.urandom(12)

    a = datetime.datetime.now()

    # opening the original file to encrypt
    with open(
        path_in,
        "rb",
    ) as file:
        original = file.read()

    # encrypting the file
    ciphertext = aesgcm.encrypt(nonce, original, aad)

    # opening the file in write mode and
    # writing the ciphertext data
    silentremove("/tmp/test.enc")
    with open("/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/tmp/test.enc", "rb") as enc_file:
        ciphertext = enc_file.read()

    # decrypting the file
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

    # opening the file in write mode and
    # writing the plaintext data
    silentremove("/tmp/test.dec")
    with open("/tmp/test.dec", "wb") as dec_file:
        dec_file.write(plaintext)

    b = datetime.datetime.now()
    delta = b - a
    print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


# def cryptography_rsa(path_in):
#     print("cryptography.hazmat rsa")

#     private_key = rsa.generate_private_key(
#         public_exponent=65537,
#         key_size=2048,
#     )
#     public_key = private_key.public_key()

#     a = datetime.datetime.now()

#     # opening the original file to encry@pt
#     with open(
#         path_in,
#         "rb",
#     ) as file:
#         original = file.read()

#     with open("/tmp/test.enc", "wb") as enc_file:
#         for chunk in funcy.chunks(128, original):
#             ciphertext = public_key.encrypt(
#                 chunk,
#                 padding.OAEP(
#                     mgf=padding.MGF1(algorithm=hashes.SHA256()),
#                     algorithm=hashes.SHA256(),
#                     label=None,
#                 ),
#             )
#             enc_file.write

#     b = datetime.datetime.now()
#     delta = b - a
#     print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

#     a = datetime.datetime.now()

#     # opening the ciphertext file
#     with open("/tmp/test.enc", "rb") as enc_file:
#         ciphertext = enc_file.read()

#     # decrypting the file
#     plaintext = private_key.decrypt(
#         ciphertext,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None,
#         ),
#     )

#     # opening the file in write mode and
#     # writing the plaintext data
#     silentremove("/tmp/test.dec")
#     with open("/tmp/test.dec", "wb") as dec_file:
#         dec_file.write(plaintext)

#     b = datetime.datetime.now()
#     delta = b - a
#     print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

#     silentremove("/tmp/test.enc")
#     silentremove("/tmp/test.dec")


def libsodium_salsa20(path_in):
    print("libsodium salsa")

    # key generation
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    # This is your safe, you can use it to encrypt or decrypt messages
    box = nacl.secret.SecretBox(key)

    a = datetime.datetime.now()

    # opening the original file to encrypt
    with open(
        path_in,
        "rb",
    ) as file:
        original = file.read()

    # encrypting the file
    ciphertext = box.encrypt(original)

    # opening the file in write mode and
    # writing the ciphertext data
    silentremove("/tmp/test.enc")
    with open("/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/tmp/test.enc", "rb") as enc_file:
        ciphertext = enc_file.read()

    # decrypting the file
    plaintext = box.decrypt(ciphertext)

    # opening the file in write mode and
    # writing the plaintext data
    silentremove("/tmp/test.dec")
    with open("/tmp/test.dec", "wb") as dec_file:
        dec_file.write(plaintext)

    b = datetime.datetime.now()
    delta = b - a
    print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


def libsodium_pubkey(path_in):
    print("libsodium pubkey")

    # Generate Bob's private key, which must be kept secret
    skbob = PrivateKey.generate()

    # Bob's public key can be given to anyone wishing to send
    pkbob = skbob.public_key

    # Alice does the same and then Alice and Bob exchange public keys
    skalice = PrivateKey.generate()
    pkalice = skalice.public_key

    bob_box = Box(skbob, pkalice)

    a = datetime.datetime.now()

    # opening the original file to encrypt
    with open(
        path_in,
        "rb",
    ) as file:
        original = file.read()

    # encrypting the file
    ciphertext = bob_box.encrypt(original)

    # opening the file in write mode and
    # writing the ciphertext data
    silentremove("/tmp/test.enc")
    with open("/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/tmp/test.enc", "rb") as enc_file:
        ciphertext = enc_file.read()

    # decrypting the file
    alice_box = Box(skalice, pkbob)
    plaintext = alice_box.decrypt(ciphertext)

    # opening the file in write mode and
    # writing the plaintext data
    silentremove("/tmp/test.dec")
    with open("/tmp/test.dec", "wb") as dec_file:
        dec_file.write(plaintext)

    b = datetime.datetime.now()
    delta = b - a
    print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pyaes(path_in):
    print("pyaes")

    # key generation
    password = "please-use-a-long-and-random-password"

    a = datetime.datetime.now()

    silentremove("/tmp/test.enc")

    # encrypting the file
    pyAesCrypt.encryptFile(path_in, "/tmp/test.enc", password)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # decrypting the file
    pyAesCrypt.decryptFile("/tmp/test.enc", "/tmp/test.dec", password)

    b = datetime.datetime.now()
    delta = b - a
    print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pycryptodome_aes(path_in):
    print("pycryptodome aesgcm")

    # key generation
    key = get_random_bytes(32)

    cipher = AES.new(key, AES.MODE_GCM)

    a = datetime.datetime.now()

    # opening the original file to encryptcrypto
    with open(
        path_in,
        "rb",
    ) as file:
        original = file.read()

    # encrypting the file
    ciphertext, tag = cipher.encrypt_and_digest(original)

    nonce = cipher.nonce

    # opening the file in write mode and
    # writing the ciphertext data
    silentremove("/tmp/test.enc")
    with open("/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/tmp/test.enc", "rb") as enc_file:
        ciphertext = enc_file.read()

    # decrypting the file
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    # opening the file in write mode and
    # writing the plaintext data
    silentremove("/tmp/test.dec")
    with open("/tmp/test.dec", "wb") as dec_file:
        dec_file.write(plaintext)

    b = datetime.datetime.now()
    delta = b - a
    print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pycryptodome_chacha20poly1305(path_in):
    print("pycryptodome chacha20poly1305")

    # key generation
    key = get_random_bytes(32)

    nonce = get_random_bytes(12)

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)

    a = datetime.datetime.now()

    # opening the original file to encryptcrypto
    with open(
        path_in,
        "rb",
    ) as file:
        original = file.read()

    # encrypting the file
    ciphertext, tag = cipher.encrypt_and_digest(original)

    nonce = cipher.nonce

    # opening the file in write mode and
    # writing the ciphertext data
    silentremove("/tmp/test.enc")
    with open("/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/tmp/test.enc", "rb") as enc_file:
        ciphertext = enc_file.read()

    # decrypting the file
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    # opening the file in write mode and
    # writing the plaintext data
    silentremove("/tmp/test.dec")
    with open("/tmp/test.dec", "wb") as dec_file:
        dec_file.write(plaintext)

    b = datetime.datetime.now()
    delta = b - a
    print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pycryptodome_chacha20(path_in):
    print("pycryptodome chacha20")

    # key generation
    key = get_random_bytes(32)

    nonce = get_random_bytes(12)

    cipher = ChaCha20.new(key=key, nonce=nonce)

    a = datetime.datetime.now()

    # opening the original file to encryptcrypto
    with open(
        path_in,
        "rb",
    ) as file:
        original = file.read()

    # encrypting the file
    ciphertext = cipher.encrypt(original)

    nonce = cipher.nonce

    # opening the file in write mode and
    # writing the ciphertext data
    silentremove("/tmp/test.enc")
    with open("/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/tmp/test.enc", "rb") as enc_file:
        ciphertext = enc_file.read()

    # decrypting the file
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    # opening the file in write mode and
    # writing the plaintext data
    silentremove("/tmp/test.dec")
    with open("/tmp/test.dec", "wb") as dec_file:
        dec_file.write(plaintext)

    b = datetime.datetime.now()
    delta = b - a
    print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pycryptodome_salsa20(path_in):
    print("pycryptodome salsa20")

    # key generation
    key = get_random_bytes(32)

    nonce = get_random_bytes(8)

    cipher = Salsa20.new(key=key, nonce=nonce)

    a = datetime.datetime.now()

    # opening the original file to encryptcrypto
    with open(
        path_in,
        "rb",
    ) as file:
        original = file.read()

    # encrypting the file
    ciphertext = cipher.encrypt(original)

    nonce = cipher.nonce

    # opening the file in write mode and
    # writing the ciphertext data
    silentremove("/tmp/test.enc")
    with open("/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/tmp/test.enc", "rb") as enc_file:
        ciphertext = enc_file.read()

    # decrypting the file
    cipher = Salsa20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    # opening the file in write mode and
    # writing the plaintext data
    silentremove("/tmp/test.dec")
    with open("/tmp/test.dec", "wb") as dec_file:
        dec_file.write(plaintext)

    b = datetime.datetime.now()
    delta = b - a
    print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pyflocker_cryptography_aes(path_in):
    from pyflocker import ciphers
    from pyflocker.ciphers import OAEP
    from pyflocker.ciphers import AES
    from pyflocker.ciphers import RSA
    from pyflocker.ciphers.backends import Backends

    print("pyflocker cryptography aes")

    key, nonce = os.urandom(32), os.urandom(16)

    deltas = []
    for _ in range(42):
        enc = AES.new(
            True,
            key,
            AES.MODE_GCM,
            nonce,
            backend=Backends.CRYPTOGRAPHY,
        )

        a = datetime.datetime.now()
        
        silentremove("/tmp/test.enc")
        buf = bytearray(128 * 1024)
        with open("/tmp/test.enc", "wb") as file_out:
            buffered_writer = io.BufferedWriter(file_out)
            for read in read_file_in_chunks(path_in, buf, chunk_size=buf.__len__()):
                ciphertext = enc.update(buf[:read])
                buffered_writer.write(ciphertext[:read])
            enc.finalize()
            buffered_writer.flush()

        b = datetime.datetime.now()
        delta = b - a
        # print("encrypt %2d MB/s" % (895 / delta.total_seconds()))
        deltas.append(delta.total_seconds())
    average = sum(deltas, 0) / len(deltas)
    print("encrypt %2d MB/s" % (895 / average))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pyflocker_cryptography_chacha20(path_in):
    from pyflocker import ciphers
    from pyflocker.ciphers import OAEP
    from pyflocker.ciphers import AES
    from pyflocker.ciphers import RSA
    from pyflocker.ciphers.backends import Backends

    print("pyflocker cryptography chacha20")

    key, nonce = os.urandom(32), os.urandom(12)
    enc = ciphers.ChaCha20.new(
        True,
        key,
        nonce,
        backend=Backends.CRYPTOGRAPHY,
    )

    # opening the original file to encryptcrypto
    with open(
        path_in,
        "rb",
    ) as file:
        original = file.read()

    silentremove("/tmp/test.enc")

    a = datetime.datetime.now()

    with open(
        "/tmp/test.enc",
        "wb",
    ) as file:
        file.write(enc.update(original))
    enc.finalize()

    # enc.update_into(f2)
    # tag = enc.calculate_tag()

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pyflocker_cryptomode_aes(path_in):
    from pyflocker import ciphers
    from pyflocker.ciphers import OAEP
    from pyflocker.ciphers import AES
    from pyflocker.ciphers import RSA
    from pyflocker.ciphers.backends import Backends

    print("pyflocker cryptomode aes")

    key, nonce = os.urandom(32), os.urandom(16)
    enc = AES.new(
        True,
        key,
        AES.MODE_GCM,
        nonce,
        backend=Backends.CRYPTODOME,
    )

    # opening the original file to encryptcrypto
    with open(
        path_in,
        "rb",
    ) as file:
        original = file.read()

    silentremove("/tmp/test.enc")

    a = datetime.datetime.now()

    with open(
        "/tmp/test.enc",
        "wb",
    ) as file:
        file.write(enc.update(original))
    enc.finalize()

    # enc.update_into(f2)
    # tag = enc.calculate_tag()

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pyflocker_cryptomode_chacha20(path_in):
    from pyflocker import ciphers
    from pyflocker.ciphers import OAEP
    from pyflocker.ciphers import AES
    from pyflocker.ciphers import RSA
    from pyflocker.ciphers.backends import Backends

    print("pyflocker cryptomode chacha20")

    key, nonce = os.urandom(32), os.urandom(12)
    enc = ciphers.ChaCha20.new(
        True,
        key,
        nonce,
        backend=Backends.CRYPTODOME,
    )

    # opening the original file to encryptcrypto
    with open(
        path_in,
        "rb",
    ) as file:
        original = file.read()

    silentremove("/tmp/test.enc")

    a = datetime.datetime.now()

    with open(
        "/tmp/test.enc",
        "wb",
    ) as file:
        file.write(enc.update(original))
    enc.finalize()

    # enc.update_into(f2)
    # tag = enc.calculate_tag()

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pyflocker_cryptography_rsa(path_in):
    from pyflocker import ciphers
    from pyflocker.ciphers import OAEP
    from pyflocker.ciphers import AES
    from pyflocker.ciphers import RSA
    from pyflocker.ciphers.backends import Backends

    print("pyflocker cryptography rsa")

    # Step 1: Generate RSA keys
    key_size = 2048  # You can choose other sizes like 1024, 4096, etc.
    private_key = RSA.generate(key_size, backend=Backends.CRYPTOGRAPHY)
    public_key = private_key.public_key()

    # Create an AES cipher with session key:
    # This will be used to encrypt an arbitrary amount of data.
    session_key, nonce = os.urandom(32), os.urandom(16)
    cipher_aes = AES.new(
        True,
        session_key,
        AES.MODE_GCM,
        nonce,
        use_hmac=True,
        backend=Backends.CRYPTOGRAPHY,
    )

    # Use the public key to encrypt the session key.
    cipher_rsa = public_key.encryptor(OAEP())
    enc_session_key = cipher_rsa.encrypt(session_key)

    a = datetime.datetime.now()

    with open(path_in, "rb") as file:
        ciphertext = cipher_aes.update(file.read())

    # Calculate the cipher tag
    cipher_aes.finalize()
    tag = cipher_aes.calculate_tag()

    with open("/tmp/test.enc", "wb") as file:
        file.write(
            b"".join(
                (
                    enc_session_key,
                    nonce,
                    tag,
                    ciphertext,
                )
            )
        )
        file.flush()

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # Read the encrypted file and separate the parts.
    with open("/tmp/test.enc", "rb") as file:
        (
            enc_session_key,
            nonce,
            tag,
            ciphertext,
        ) = [file.read(n) for n in (private_key.n.bit_length() // 8, 16, 16, -1)]

    # Decrypt the session key and create a cipher.
    dec = private_key.decryptor(OAEP())
    session_key = dec.decrypt(enc_session_key)

    cipher_aes = AES.new(
        False,
        session_key,
        AES.MODE_GCM,
        nonce,
        use_hmac=True,
    )

    # Decrypt the ciphertext and verify the decryption.
    plaintext = cipher_aes.update(ciphertext)
    cipher_aes.finalize(tag)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/tmp/test.enc")
    silentremove("/tmp/test.dec")


# cryptography_fernet(
#     "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
print()
cryptography_chacha20poly1305(
    "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
)
print()
cryptography_aesgcm(
    "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
)
# print()
# cryptography_aesgcmsiv(
#     "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# cryptography_cast5(
#     "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# cryptography_rsa(
#     "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# libsodium_salsa20(
#     "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# libsodium_pubkey(
#     "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pyaes(
#     "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pycryptodome_aes(
#     "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pycryptodome_chacha20poly1305(
#     "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pycryptodome_chacha20(
#     "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pycryptodome_salsa20(
#     "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
print()
pyflocker_cryptography_aes(
    "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
)
# print()
# pyflocker_cryptography_chacha20(
#     "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pyflocker_cryptomode_aes(
#     "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pyflocker_cryptomode_chacha20(
#     "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pyflocker_cryptography_rsa(
#     "/home/gnome/Downloads/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
