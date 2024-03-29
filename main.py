import os
import csv
import ast  # to convert string back to bytes
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MASTER_KEY = "IAMTHEPERMANENTKEY"
KEY_SLUG = "origin"
original_file = "text.txt"
FILE_TO_ENCRYPT = "text_to_encrypt.txt"
open(FILE_TO_ENCRYPT, 'wb').write(open(original_file, 'rb').read())


def split_bytes_key_iv(key):
    """
    Generates a SHA-256 hash of the provided key and splits it into two parts.

    The first part is the complete hash used as the key, and the second part
    (first half of the hash) is used as the initialization vector (IV).

    Parameters:
    key (str): The input key for generating hash.

    Returns:
    tuple: A tuple containing the full hash and the first half of the hash.
    """
    hash_object = hashlib.sha256(b'{key}')
    dig = hash_object.digest()
    midpoint = len(dig) // 2
    return dig, dig[:midpoint]


def cipher_data(key, iv):
    """
    Creates a cipher object along with encryptor and decryptor for AES encryption.

    Parameters:
    key (bytes): The encryption key.
    iv (bytes): The initialization vector.

    Returns:
    tuple: A tuple containing the cipher, encryptor, decryptor, and buffer size.
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    return cipher, encryptor, decryptor, 1024


def save_csv(data, title):
    """
    Saves a dictionary of data into a CSV file.

    Parameters:
    data (dict): The data to be written to the CSV.
    title (str): The name of the CSV file to be saved.

    Returns:
    str: The filename of the saved CSV file.
    """
    file = f"{title}"
    with open(file, 'w') as f:
        w = csv.DictWriter(f, data.keys())
        w.writeheader()
        w.writerow(data)
    return file


def read_keys_from_csv(file):
    """
    Reads the encryption key and IV from a CSV file.

    Parameters:
    file (str): The name of the CSV file to read from.

    Returns:
    tuple: A tuple containing the encryption key and IV.
    """
    with open(file, "r") as f:
        reader = csv.DictReader(f, ['key', 'iv'])
        next(reader, None)  # skip the headers
        for row in reader:
            secrets = row["key"], row["iv"]
        os.remove(file)
        loadedKey, loadedIV = secrets
        return loadedKey, loadedIV


def encrypt_file(file, encryptor, BUF_SIZE):
    """
    Encrypts a file using the provided encryptor and buffer size.

    Parameters:
    file (str): The name of the file to encrypt.
    encryptor (Cipher.encryptor): The encryptor to use for encryption.
    BUF_SIZE (int): The buffer size for reading the file.

    Returns:
    None
    """
    encFile = f"encrypted_{file}"
    f1 = open(encFile, 'wb')
    with open(file, 'rb') as f2:
        while True:
            data = f2.read(BUF_SIZE)

            if (len(data) > 0):
                ct = encryptor.update(data)
                f1.write(ct)
            else:
                break

    f2.close()
    f1.close()
    os.remove(file)


def decrypt_file(file, decryptor, BUF_SIZE):
    """
    Decrypts a file using the provided decryptor.

    Parameters:
    file (str): The name of the file to decrypt.
    decryptor (Cipher.decryptor): The decryptor to use for decryption.
    BUF_SIZE (int): The buffer size for reading the file.

    Returns:
    str: The name of the decrypted file.
    """
    decrypted_file = f"decrypted_{file}"
    f1 = open(decrypted_file, 'wb')
    with open(file, 'rb') as f2:
        while True:
            data = f2.read(BUF_SIZE)
            if (len(data) > 0):
                pt = decryptor.update(data)
                f1.write(pt)
            else:
                break

    f2.close()
    f1.close()
    return decrypted_file


def get_keys(password):
    """
    Decrypts and retrieves the encryption key and IV using the provided password.

    Parameters:
    password (str): The password used to decrypt and retrieve the key and IV.

    Returns:
    tuple: A tuple containing the decrypted key and IV.
    """
    pass_key, pass_iv = split_bytes_key_iv(password)
    cipher, encryptor, decryptor, BUF_SIZE = cipher_data(pass_key, pass_iv)
    decrypted_keys = decrypt_file(f"encrypted_{KEY_SLUG}", encryptor, BUF_SIZE)
    k, iv = read_keys_from_csv(decrypted_keys)
    return ast.literal_eval(k), ast.literal_eval(iv)


def registerPassword(password, MASTER_KEY):
    """
    Encrypts and registers a password for later use in encryption/decryption.

    Parameters:
    password (str): The user's password.
    MASTER_KEY (str): The master key used for initial encryption.

    Returns:
    None
    """
    master_key, master_iv = split_bytes_key_iv(MASTER_KEY)
    keyData = {"key": master_key, "iv": master_iv}
    keys_file = save_csv(keyData, KEY_SLUG)

    pass_key, pass_iv = split_bytes_key_iv(password)
    cipher, encryptor, decryptor, BUF_SIZE = cipher_data(pass_key, pass_iv)
    encrypt_file(keys_file, encryptor, BUF_SIZE)


def encrypt_file_with_password(file, password):
    """
    Encrypts a file using a password.

    Parameters:
    file (str): The name of the file to encrypt.
    password (str): The password used for encrypting the file.

    Returns:
    None
    """
    enc_key, enc_iv = get_keys(password)
    cipher, encryptor, decryptor, BUF_SIZE = cipher_data(enc_key, enc_iv)
    encrypt_file(file, encryptor, BUF_SIZE)


def decrypt_file_with_password(file, password):
    """
    Decrypts a file that was encrypted with a password.

    Parameters:
    file (str): The name of the file to decrypt.
    password (str): The password used for decrypting the file.

    Returns:
    str: The name of the decrypted file.
    """
    file = f"encrypted_{file}"
    enc_key, enc_iv = get_keys(password)
    cipher, encryptor, decryptor, BUF_SIZE = cipher_data(enc_key, enc_iv)
    return decrypt_file(file, decryptor, BUF_SIZE)


password = str(input("Enter Password: "))
registerPassword(password, MASTER_KEY)

encrypt_file_with_password(FILE_TO_ENCRYPT, password)

decrypt_file_with_password(f"{FILE_TO_ENCRYPT}", password)
