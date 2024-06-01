import errno
import datetime
import os
import io
import shutil
import hashlib
from pathlib import Path
import concurrent.futures
import functools

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
from Crypto.Cipher import AES as CryptoAES
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Cipher import Salsa20
from Crypto.Cipher import ChaCha20
from struct import pack
from Crypto.Random import get_random_bytes

from pyflocker import ciphers
from pyflocker.ciphers import AES
from pyflocker.ciphers.backends import Backends
from pyflocker.ciphers import OAEP
from pyflocker.ciphers import AES
from pyflocker.ciphers import ChaCha20
from pyflocker.ciphers import RSA
from pyflocker import locker


def get_file_size(file_path):
    try:
        size = os.path.getsize(file_path)
        return size
    except FileNotFoundError:
        print(f"File {file_path} not found.")
    except Exception as e:
        print(f"Error retrieving size of file {file_path}: {e}")
        return None


def delete_file(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        print(f"File {path} not found.")
    except PermissionError:
        print(f"Permission denied to delete {path}.")
    except Exception as e:
        print(f"Error deleting file {path}: {e}")


def delete_dir(path):
    if os.path.exists(path):
        shutil.rmtree(path)
    else:
        print(f"Directory {path} does not exist.")


def create_directory_in_home(dir_name):
    # Get the user's home directory
    home_dir = Path.home()

    # Create the full path for the new directory
    new_dir_path = home_dir / dir_name

    # Create the directory
    try:
        new_dir_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"Error creating directory: {e}")

    return new_dir_path.absolute().__str__()


def create_file_with_size(file_path_str, size_in_bytes):
    with open(file_path_str, "wb") as f:
        for _ in range(size_in_bytes // 4096):
            f.write(os.urandom(4096))


def calculate_file_hash(file_path):
    hash_algo = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_algo.update(chunk)
    return hash_algo.hexdigest()


def compare_files_by_hash(file1, file2):
    return calculate_file_hash(file1) == calculate_file_hash(file2)


def read_file_in_chunks(file_path, buf):
    with open(file_path, "rb") as file:
        buffered_reader = io.BufferedReader(file, buffer_size=len(buf))
        while True:
            read = buffered_reader.readinto(buf)
            if read == 0:
                break
            yield read


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
    silentremove("/home/gnome/tmp/test.enc")
    with open("/home/gnome/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/home/gnome/tmp/test.enc", "rb") as enc_file:
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

    silentremove("/home/gnome/tmp/test.enc")
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
    for _ in range(3):
        a = datetime.datetime.now()

        silentremove("/home/gnome/tmp/test.enc")
        buf = bytearray(128 * 1024)
        with open("/home/gnome/tmp/test.enc", "wb") as file_out:
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
    # with open("/home/gnome/tmp/test.enc", "rb") as enc_file:
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

    silentremove("/home/gnome/tmp/test.enc")
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
    for _ in range(3):
        a = datetime.datetime.now()

        silentremove("/home/gnome/tmp/test.enc")
        buf = bytearray(128 * 1024)
        with open("/home/gnome/tmp/test.enc", "wb") as file_out:
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
    # with open("/home/gnome/tmp/test.enc", "rb") as enc_file:
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

    silentremove("/home/gnome/tmp/test.enc")
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
    ciphertext = cipher.update(original)

    # opening the file in write mode and
    # writing the ciphertext data
    silentremove("/home/gnome/tmp/test.enc")
    with open("/home/gnome/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/home/gnome/tmp/test.enc", "rb") as enc_file:
        ciphertext = enc_file.read()

    # decrypting the file
    decryptor = cipher.decryptor()
    plaintext = cipher.update(ciphertext)

    # opening the file in write mode and
    # writing the plaintext data
    silentremove("/tmp/test.dec")
    with open("/tmp/test.dec", "wb") as dec_file:
        dec_file.write(plaintext)

    b = datetime.datetime.now()
    delta = b - a
    print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/home/gnome/tmp/test.enc")
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
    silentremove("/home/gnome/tmp/test.enc")
    with open("/home/gnome/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/home/gnome/tmp/test.enc", "rb") as enc_file:
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

    silentremove("/home/gnome/tmp/test.enc")
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

#     with open("/home/gnome/tmp/test.enc", "wb") as enc_file:
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
#     with open("/home/gnome/tmp/test.enc", "rb") as enc_file:
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

#     silentremove("/home/gnome/tmp/test.enc")
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
    silentremove("/home/gnome/tmp/test.enc")
    with open("/home/gnome/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/home/gnome/tmp/test.enc", "rb") as enc_file:
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

    silentremove("/home/gnome/tmp/test.enc")
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
    silentremove("/home/gnome/tmp/test.enc")
    with open("/home/gnome/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/home/gnome/tmp/test.enc", "rb") as enc_file:
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

    silentremove("/home/gnome/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pyaes(path_in):
    print("pyaes")

    # key generation
    password = "please-use-a-long-and-random-password"

    a = datetime.datetime.now()

    silentremove("/home/gnome/tmp/test.enc")

    # encrypting the file
    pyAesCrypt.encryptFile(path_in, "/home/gnome/tmp/test.enc", password)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # decrypting the file
    pyAesCrypt.decryptFile("/home/gnome/tmp/test.enc", "/tmp/test.dec", password)

    b = datetime.datetime.now()
    delta = b - a
    print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/home/gnome/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pycryptodome_aes(path_in):
    print("pycryptodome aesgcm")

    # key generation
    key = get_random_bytes(32)

    cipher = CryptoAES.new(key, CryptoAES.MODE_GCM)

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
    silentremove("/home/gnome/tmp/test.enc")
    with open("/home/gnome/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/home/gnome/tmp/test.enc", "rb") as enc_file:
        ciphertext = enc_file.read()

    # decrypting the file
    cipher = CryptoAES.new(key, CryptoAES.MODE_GCM, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    # opening the file in write mode and
    # writing the plaintext data
    silentremove("/tmp/test.dec")
    with open("/tmp/test.dec", "wb") as dec_file:
        dec_file.write(plaintext)

    b = datetime.datetime.now()
    delta = b - a
    print("decrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/home/gnome/tmp/test.enc")
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
    silentremove("/home/gnome/tmp/test.enc")
    with open("/home/gnome/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/home/gnome/tmp/test.enc", "rb") as enc_file:
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

    silentremove("/home/gnome/tmp/test.enc")
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
    silentremove("/home/gnome/tmp/test.enc")
    with open("/home/gnome/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/home/gnome/tmp/test.enc", "rb") as enc_file:
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

    silentremove("/home/gnome/tmp/test.enc")
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
    silentremove("/home/gnome/tmp/test.enc")
    with open("/home/gnome/tmp/test.enc", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    a = datetime.datetime.now()

    # opening the ciphertext file
    with open("/home/gnome/tmp/test.enc", "rb") as enc_file:
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

    silentremove("/home/gnome/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pyflocker_cryptography_aesgcm(path_in):
    print("pyflocker cryptography aesgcm")

    key, nonce = os.urandom(32), os.urandom(16)

    deltas = []
    for _ in range(3):
        enc = AES.new(
            True,
            key,
            AES.MODE_GCM,
            nonce,
            backend=Backends.CRYPTOGRAPHY,
        )

        a = datetime.datetime.now()

        silentremove("/home/gnome/tmp/test.enc")
        with open("/home/gnome/tmp/test.enc", "wb") as file_out:
            buffered_writer = io.BufferedWriter(file_out)
            for buf in read_file_in_chunks(path_in, update_intochunk_size=128 * 1024):
                ciphertext = enc.update(buf)
                buffered_writer.write(ciphertext)
            enc.finalize()
            buffered_writer.flush()

        b = datetime.datetime.now()
        delta = b - a
        # print("encrypt %2d MB/s" % (895 / delta.total_seconds()))
        deltas.append(delta.total_seconds())
    average = sum(deltas, 0) / len(deltas)
    print("encrypt %2d MB/s" % (895 / average))

    silentremove("/home/gnome/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pyflocker_cryptography_chacha20(path_in):
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

    silentremove("/home/gnome/tmp/test.enc")

    a = datetime.datetime.now()

    with open(
        "/home/gnome/tmp/test.enc",
        "wb",
    ) as file:
        file.writeupdate_into(enc.update(original))
    enc.finalize()

    # enc.update_into(f2)
    # tag = enc.calculate_tag()

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/home/gnome/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pyflocker_cryptomode_aes(path_in):
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

    silentremove("/home/gnome/tmp/test.enc")

    a = datetime.datetime.now()

    with open(
        "/home/gnome/tmp/test.enc",
        "wb",
    ) as file:
        file.writeupdate_into(enc.update(original))
    enc.finalize()

    # enc.update_into(f2)
    # tag = enc.calculate_tag()

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/home/gnome/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pyflocker_cryptomode_chacha20(path_in):
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

    silentremove("/home/gnome/tmp/test.enc")

    a = datetime.datetime.now()

    with open(
        "/home/gnome/tmp/test.enc",
        "wb",
    ) as file:
        file.writeupdate_into(enc.update(original))
    enc.finalize()

    # enc.update_into(f2)
    # tag = enc.calculate_tag()

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/home/gnome/tmp/test.enc")
    silentremove("/tmp/test.dec")


def pyflocker_cryptography_rsa(path_in):
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
        ciphertextupdate_into = cipher_aes.update(file.read())

    # Calculate the cipher tag
    cipher_aes.finalize()
    tag = cipher_aes.calculate_tag()

    with open("/home/gnome/tmp/test.enc", "wb") as file:
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
    with open("/home/gnome/tmp/test.enc", "rb") as file:
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

    # Decrypt the ciphertext and verify the deupdate_intocryption.
    plaintext = cipher_aes.update(ciphertext)
    cipher_aes.finalize(tag)

    b = datetime.datetime.now()
    delta = b - a
    print("encrypt %2d MB/s" % (895 / delta.total_seconds()))

    silentremove("/home/gnome/tmp/test.enc")
    silentremove("/tmp/test.dec")


def copy_file_shutil(path_in, path_out):
    deltas = []
    for _ in range(1):
        a = datetime.datetime.now()

        silentremove(path_out)
        shutil.copy(path_in, path_out)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    silentremove(path_out)

    average = sum(deltas, 0) / len(deltas)
    filesize = get_file_size(path_in)
    print(f"| {(filesize / 1024 / 1024):.5g} | {average:.5f} |")


def pyflocker_encrypt_into(block_len):
    key = os.urandom(32)

    plaintext = os.urandom(block_len)
    ciphertext = bytearray(block_len + 28)

    deltas = []
    for _ in range(3):
        a = datetime.datetime.now()

        nonce = os.urandom(16)
        cipher = AES.new(True, key, AES.MODE_GCM, nonce, backend=Backends.CRYPTOGRAPHY)
        cipher.update_into(plaintext, ciphertext)
        cipher.finalize()
        cipher.calculate_tag()

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def pyflocker_encrypt(block_len):
    key = os.urandom(32)

    plaintext = os.urandom(block_len)

    deltas = []
    for _ in range(3):
        a = datetime.datetime.now()

        nonce = os.urandom(16)
        cipher = AES.new(True, key, AES.MODE_GCM, nonce, backend=Backends.CRYPTOGRAPHY)
        cipher.update(plaintext)
        cipher.finalize()
        cipher.calculate_tag()

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def pyflocker_encrypt_file_locker(path_in, path_out):
    password = b"my-super-secret-password"

    deltas = []
    for _ in range(3):
        a = datetime.datetime.now()
        locker.lockerf(
            open(path_in, "rb"),
            open(path_out, "wb"),
            password,
            encrypting=True,
            aes_mode=AES.MODE_GCM,
        )

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    silentremove(path_out)

    average = sum(deltas, 0) / len(deltas)
    print(f"| {average:.5f} |")


def pyflocker_encrypt_file_chunks(path_in, path_out):
    chunk_len = 256 * 1024

    key = os.urandom(32)

    ciphertext = bytearray(chunk_len + 28)

    deltas = []
    for _ in range(3):
        silentremove(path_out)

        a = datetime.datetime.now()

        with open(path_out, "wb", buffering=chunk_len + 28) as file_out:
            for read in read_file_in_chunks(path_in, ciphertext[:chunk_len]):
                nonce = os.urandom(16)
                cipher = AES.new(
                    True,
                    key,
                    AES.MODE_GCM,
                    nonce,
                    backend=Backends.CRYPTOGRAPHY,
                )
                cipher.update_into(ciphertext[:chunk_len], ciphertext)
                cipher.finalize()
                tag = cipher.calculate_tag()
                file_out.write(ciphertext[:read])
                file_out.write(tag)
                file_out.write(nonce)
            file_out.flush()

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    silentremove(path_out)

    average = sum(deltas, 0) / len(deltas)
    filesize = get_file_size(path_in)
    print(f"| {(filesize / 1024 / 1024):.5g} | {average:.5f} |")


def read_chunks(path_in, chunk_len):
    with open(path_in, "rb") as file:
        while True:
            buf = file.read(chunk_len)
            if not buf:
                break
            yield buf


def write_chunk(path_out, chunk, offset):
    with open(path_out, "r+b") as file_out:
        file_out.seek(offset)
        file_out.write(chunk)


def copy_file_par(path_in, path_out):
    chunk_len = 2 * 1024 * 1024  # 2 MB

    if not os.path.exists(path_in):
        print(f"Input file {path_in} does not exist.")
        return

    a = datetime.datetime.now()

    # Create the output file and set its size to match the input file
    input_size = os.path.getsize(path_in)
    with open(path_out, "wb") as file_out:
        file_out.truncate(input_size)

    # Read and write chunks in parallel
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            offset = 0
            for chunk in read_chunks(path_in, chunk_len):
                future = executor.submit(write_chunk, path_out, chunk, offset)
                futures.append(future)
                offset += chunk_len

            # Ensure all futures are completed
            concurrent.futures.wait(futures)
    except Exception as e:
        print(f"An error occurred: {e}")

    b = datetime.datetime.now()
    delta = b - a
    filesize = get_file_size(path_in)
    print(f"| {(filesize / 1024 / 1024):.5g} | {delta.total_seconds():.5f} |")


def pyflocker_decrypt_into(block_len):
    key = os.urandom(32)

    plaintext = os.urandom(block_len)
    ciphertext = bytearray(block_len + 28)

    deltas = []
    for _ in range(3):
        nonce = os.urandom(16)
        cipher = AES.new(
            True,
            key,
            AES.MODE_GCM,
            nonce,
            backend=Backends.CRYPTOGRAPHY,
        )
        cipher.update_into(plaintext, ciphertext)
        cipher.finalize()
        tag = cipher.calculate_tag()

        a = datetime.datetime.now()

        cipher = AES.new(
            False,
            key,
            AES.MODE_GCM,
            nonce,
            backend=Backends.CRYPTOGRAPHY,
        )
        plaintext2 = bytearray(block_len + 1024)
        cipher.update_into(ciphertext, plaintext2)
        # cipher.finalize(tag)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

        # assert plaintext == plaintext2

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def pyflocker_decrypt(block_len):
    key = os.urandom(32)

    plaintext = os.urandom(block_len)
    ciphertext = bytearray(block_len + 28)

    deltas = []
    for _ in range(3):
        nonce = os.urandom(16)
        cipher = AES.new(
            True,
            key,
            AES.MODE_GCM,
            nonce,
            backend=Backends.CRYPTOGRAPHY,
        )
        cipher.update_into(plaintext, ciphertext)
        cipher.finalize()
        tag = cipher.calculate_tag()

        a = datetime.datetime.now()

        cipher = AES.new(
            False,
            key,
            AES.MODE_GCM,
            nonce,
            backend=Backends.CRYPTOGRAPHY,
        )
        plaintext2 = cipher.update(ciphertext)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

        # assert plaintext == plaintext2

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


def pyflocker_decrypt_file_locker(path_in, path_out):
    password = b"my-super-secret-password"
    tmp = "/home/gnome/tmp/test.dec"

    locker.lockerf(
        open(path_in, "rb"),
        open(path_out, "wb"),
        password,
        encrypting=True,
        aes_mode=AES.MODE_GCM,
    )

    deltas = []
    for _ in range(3):
        a = datetime.datetime.now()

        locker.lockerf(
            open(path_out, "rb"),
            open(tmp, "wb"),
            password,
            encrypting=False,
            aes_mode=AES.MODE_GCM,
        )

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    silentremove(path_out)

    average = sum(deltas, 0) / len(deltas)
    print(f"| {average:.5f} |")


def pyflocker_decrypt_file_chunks(path_in, path_out):
    chunk_len = 2 * 1024 * 1024

    key = os.urandom(32)

    buf = bytearray(chunk_len + 28)

    tmp = "/home/gnome/tmp/test.dec"

    silentremove(path_out)
    with open(path_out, "wb", buffering=chunk_len + 28) as file_out:
        for read in read_file_in_chunks(path_in, buf[:chunk_len]):
            nonce = os.urandom(16)
            cipher = AES.new(
                True,
                key,
                AES.MODE_GCM,
                nonce,
                backend=Backends.CRYPTOGRAPHY,
            )
            cipher.update_into(buf[:read], buf)
            cipher.finalize()
            tag = cipher.calculate_tag()
            file_out.write(buf)
            file_out.write(tag)
            file_out.write(nonce)
        file_out.flush()

    deltas = []
    for _ in range(3):
        a = datetime.datetime.now()

        with open(tmp, "wb", buffering=chunk_len) as file_out:
            for read in read_file_in_chunks(path_in, buf):
                tag = bytes(buf[read - 28 : read - 28 + 16])
                nonce = bytes(buf[read - 12 : read])
                cipher = AES.new(
                    False,
                    key,
                    AES.MODE_GCM,
                    nonce,
                    backend=Backends.CRYPTOGRAPHY,
                )
                cipher.update_into(buf[:read - 28], buf)
                # cipher.finalize(tag)
                file_out.write(buf[:read - 28])
            file_out.flush()

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    compare_files_by_hash(path_in, tmp)
    silentremove(path_out)
    silentremove(tmp)

    average = sum(deltas, 0) / len(deltas)
    filesize = get_file_size(path_in)
    print(f"| {(filesize / 1024 / 1024):.5g} | {average:.5f} |")

def copy_file(fin, fout):
    chunk_len = 256 * 1024
    buf = bytearray(chunk_len)

    silentremove(fout)

    deltas = []
    for _ in range(3):

        a = datetime.datetime.now()

        with open(fout, "wb", buffering=chunk_len) as file_out:
            for read in read_file_in_chunks(fin, buf):
                file_out.write(buf[:read])
            file_out.flush()

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    silentremove(fout)

    average = sum(deltas, 0) / len(deltas)
    filesize = get_file_size(fin)
    print(f"| {(filesize / 1024 / 1024):.5g} | {average:.5f} |")



def cryptography_encrypt(block_len):
    aad = b"authenticated but unciphertext data"
    key = AESGCM.generate_key(256)

    plaintext = os.urandom(block_len)

    deltas = []
    for _ in range(3):
        a = datetime.datetime.now()

        cipher = AESGCM(key)
        nonce = os.urandom(12)
        cipher.encrypt(nonce, plaintext, aad)

        b = datetime.datetime.now()
        delta = b - a
        deltas.append(delta.total_seconds())

    average = sum(deltas, 0) / len(deltas)
    print(f"| {block_len/1024/1024} | {average:.5f} |")


# cryptography_fernet(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# cryptography_chacha20poly1305(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# cryptography_aesgcm(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# cryptography_aesgcmsiv(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# cryptography_cast5(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# cryptography_rsa(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# libsodium_salsa20(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# libsodium_pubkey(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pyaes(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pycryptodome_aes(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pycryptodome_chacha20poly1305(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pycryptodome_chacha20(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pycryptodome_salsa20(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pyflocker_cryptography_aesgcm(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pyflocker_cryptography_chacha20(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pyflocker_cryptomode_aes(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pyflocker_cryptomode_chacha20(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )
# print()
# pyflocker_cryptography_rsa(
#     "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
# )

tmp_dir = create_directory_in_home("rencrypt_tmp")
sizes_mb = [
    0.03125,
    0.0625,
    0.125,
    0.25,
    0.5,
    1,
    2,
    4,
    8,
    16,
    32,
    64,
    128,
    256,
    512,
    1024,
    2 * 1024,
    4 * 1024,
    # 8 * 1024,
    # 16 * 1024,
]

print("pyflocker_encrypt_into")
print("| MB    | Seconds |")
print("| ----- | ------- |")
pyflocker_encrypt_into(32 * 1024)
pyflocker_encrypt_into(64 * 1024)
pyflocker_encrypt_into(128 * 1024)
pyflocker_encrypt_into(256 * 1024)
pyflocker_encrypt_into(512 * 1024)
pyflocker_encrypt_into(1024 * 1024)
pyflocker_encrypt_into(2 * 1024 * 1024)
pyflocker_encrypt_into(4 * 1024 * 1024)
pyflocker_encrypt_into(8 * 1024 * 1024)
pyflocker_encrypt_into(16 * 1024 * 1024)
pyflocker_encrypt_into(32 * 1024 * 1024)
pyflocker_encrypt_into(64 * 1024 * 1024)
pyflocker_encrypt_into(128 * 1024 * 1024)
pyflocker_encrypt_into(256 * 1024 * 1024)
pyflocker_encrypt_into(512 * 1024 * 1024)
pyflocker_encrypt_into(1024 * 1024 * 1024)

print("\n pyflocker_encrypt")
print("| MB    | Seconds |")
print("| ----- | ------- |")
pyflocker_encrypt(32 * 1024)
pyflocker_encrypt(64 * 1024)
pyflocker_encrypt(128 * 1024)
pyflocker_encrypt(256 * 1024)
pyflocker_encrypt(512 * 1024)
pyflocker_encrypt(1024 * 1024)
pyflocker_encrypt(2 * 1024 * 1024)
pyflocker_encrypt(4 * 1024 * 1024)
pyflocker_encrypt(8 * 1024 * 1024)
pyflocker_encrypt(16 * 1024 * 1024)
pyflocker_encrypt(32 * 1024 * 1024)
pyflocker_encrypt(64 * 1024 * 1024)
pyflocker_encrypt(128 * 1024 * 1024)
pyflocker_encrypt(256 * 1024 * 1024)
pyflocker_encrypt(512 * 1024 * 1024)
pyflocker_encrypt(1024 * 1024 * 1024)

path_in = "/home/gnome/tmp/Zero.Days.2016.720p.WEBRip.x264.AAC-ETRG.mp4"
path_out = "/home/gnome/tmp/test.enc"
print("\n pyflocker_encrypt_file_locker")
print("| Seconds |")
print("| ------- |")
pyflocker_encrypt_file_locker(path_in, path_out)

print("\n encrypt_file")
print("| MB | Seconds |")
print("| -- | ------- |")
for size in sizes_mb:
    file_path = f"{tmp_dir}/test_{size}M.raw"
    create_file_with_size(file_path, int(size * 1024 * 1024))
    pyflocker_encrypt_file_chunks(file_path, file_path + ".enc")
    delete_file(file_path)

print("\n pyflocker_decrypt_into")
print("| MB    | Seconds |")
print("| ----- | ------- |")
pyflocker_decrypt_into(32 * 1024)
pyflocker_decrypt_into(64 * 1024)
pyflocker_decrypt_into(128 * 1024)
pyflocker_decrypt_into(256 * 1024)
pyflocker_decrypt_into(512 * 1024)
pyflocker_decrypt_into(1024 * 1024)
pyflocker_decrypt_into(2 * 1024 * 1024)
pyflocker_decrypt_into(4 * 1024 * 1024)
pyflocker_decrypt_into(8 * 1024 * 1024)
pyflocker_decrypt_into(16 * 1024 * 1024)
pyflocker_decrypt_into(32 * 1024 * 1024)
pyflocker_decrypt_into(64 * 1024 * 1024)
pyflocker_decrypt_into(128 * 1024 * 1024)
pyflocker_decrypt_into(256 * 1024 * 1024)
pyflocker_decrypt_into(512 * 1024 * 1024)
pyflocker_decrypt_into(1024 * 1024 * 1024)

print("\n pyflocker_decrypt")
print("| MB    | Seconds |")
print("| ----- | ------- |")
pyflocker_decrypt(32 * 1024)
pyflocker_decrypt(64 * 1024)
pyflocker_decrypt(128 * 1024)
pyflocker_decrypt(256 * 1024)
pyflocker_decrypt(512 * 1024)
pyflocker_decrypt(1024 * 1024)
pyflocker_decrypt(2 * 1024 * 1024)
pyflocker_decrypt(4 * 1024 * 1024)
pyflocker_decrypt(8 * 1024 * 1024)
pyflocker_decrypt(16 * 1024 * 1024)
pyflocker_decrypt(32 * 1024 * 1024)
pyflocker_decrypt(64 * 1024 * 1024)
pyflocker_decrypt(128 * 1024 * 1024)
pyflocker_decrypt(256 * 1024 * 1024)
pyflocker_decrypt(512 * 1024 * 1024)
pyflocker_decrypt(1024 * 1024 * 1024)

print("\n pyflocker_decrypt_file_chunks")
print("| MB | Seconds |")
print("| -- | ------- |")
for size in sizes_mb:
    file_path = f"{tmp_dir}/test_{size}M.raw"
    create_file_with_size(file_path, int(size * 1024 * 1024))
    pyflocker_decrypt_file_chunks(file_path, file_path + ".enc")
    delete_file(file_path)

print("\n cryptography_encrypt")
print("| MB    | Seconds |")
print("| ----- | ------- |")
cryptography_encrypt(32 * 1024)
cryptography_encrypt(64 * 1024)
cryptography_encrypt(128 * 1024)
cryptography_encrypt(256 * 1024)
cryptography_encrypt(512 * 1024)
cryptography_encrypt(1024 * 1024)
cryptography_encrypt(2 * 1024 * 1024)
cryptography_encrypt(4 * 1024 * 1024)
cryptography_encrypt(8 * 1024 * 1024)
cryptography_encrypt(16 * 1024 * 1024)
cryptography_encrypt(32 * 1024 * 1024)
cryptography_encrypt(64 * 1024 * 1024)
cryptography_encrypt(128 * 1024 * 1024)
cryptography_encrypt(256 * 1024 * 1024)
cryptography_encrypt(512 * 1024 * 1024)
cryptography_encrypt(1024 * 1024 * 1024)

delete_dir(tmp_dir)
