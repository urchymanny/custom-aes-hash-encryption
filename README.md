# custom-aes-hash-encryption
 a custom implementation of a file encryption and decryption system using AES in CTR mode from the cryptography library

The script includes functionality for encrypting and decrypting files, managing keys, and handling data in various formats (such as byte arrays and CSV files). Here's a breakdown of its key components and processes:

## 1. Key Generation and Management:

- `split_bytes_key_iv`: Generates a SHA-256 hash of a given key and splits it into two parts to use as the AES key and the initialization vector (IV).
- `registerPassword`: Encrypts and saves the master key and IV in a CSV file using a user-provided password.
- `get_keys`: Decrypts the master key and IV from the CSV file using the user's password.

## 2. Encryption and Decryption Process:
- `cipher_data`: Creates a cipher object for encryption and decryption, along with an encryptor and decryptor object.
- `encrypt_file` / `decrypt_file`: Encrypts or decrypts a file in chunks to handle large files efficiently.
- `encrypt_file_with_password` / `decrypt_file_with_password`: Wrapper functions that handle the process of encrypting or decrypting a file using a password provided by the user.

## 3. File Handling:

- `save_csv` / `read_keys_from_csv`: Functions for saving and reading key data to and from a CSV file.
- The script uses the os module to handle file operations like reading, writing, and removing files.

## 4. Execution Flow:

The script prompts the user for a password.
It registers this password using registerPassword, which involves encrypting and saving the master key.
The script then encrypts and decrypts a file (FILE_TO_ENCRYPT) using the provided password.

## 5. Security Considerations:
The use of AES in CTR mode for encryption is a strong choice for file encryption.
The generation of the key and IV from a hash of the password (and master key) is a reasonable approach, but it's important to note that the security of this system heavily depends on the strength of the passwords used.

### Potential Improvements:
- Implement error handling for cryptographic operations and file I/O.
