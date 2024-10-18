# AES Encryption and Decryption

## Description

This project implements the Advanced Encryption Standard (AES) with support for all key lengths (128-bit, 192-bit, and 256-bit) for both encryption and decryption. AES is a symmetric block cipher that uses a secret key to securely encrypt and decrypt messages. The project can process 16-byte message blocks, ensuring security across different key lengths.

## Overview of AES

AES (Advanced Encryption Standard) is a widely-used symmetric encryption algorithm designed to securely protect electronic data. It supports three key lengths: 128, 192, and 256 bits. This project implements AES with all key lengths, enabling secure encryption and decryption of 16-byte message blocks.

## Project Structure

- **AES.py**: Contains the core implementation of the AES encryption and decryption algorithms.
- **AES_test.py**: Contains test cases to run the AES functions and verify their functionality.

## Prerequisites

- Python version 3.12.6 or later.

## How to Run

1. Open a terminal window.
2. Navigate to the project directory using the `cd` command.
3. Run the following command to execute the test script:

    ```bash
    python AES_test.py
    ```

4. Follow the script's prompts:
    - Enter `"e"` for encryption or `"d"` for decryption.
    - Enter the desired key size (128, 192, or 256).
    - Enter the secret key (ensure its length matches the chosen key size).
    - Depending on your choice (encryption or decryption), input either the plain text or ciphertext.

## Notes

- Ensure that the secret key length matches the selected key size (16 bytes for 128-bit, 24 bytes for 192-bit, and 32 bytes for 256-bit keys).

# RSA Encryption and Decryption

## Description

This project implements the RSA (Rivest-Shamir-Adleman) encryption algorithm It randomly selects two prime numbers from a txt file of prime numbers and 
uses them to produce the public and private keys. Using the keys, providing secure encryption and decryption for sensitive data. RSA is an asymmetric encryption algorithm that uses a pair of keys – a public key for encryption and a private key for decryption. The project is capable of securely encrypting and decrypting messages of varying lengths, depending on the key size used, ensuring robust security for digital communication and data protection..

## Overview of AES

RSA (Rivest-Shamir-Adleman) is one of the most widely-used asymmetric encryption algorithms designed to securely protect electronic data. It operates using two keys: a public key for encryption and a private key for decryption. RSA supports various key lengths, commonly ranging from 1024 to 4096 bits. This project implements RSA encryption and decryption, allowing secure communication by encrypting data with the public key and decrypting it with the corresponding private key.

## Project Structure

- **RSA.py**: Contains the core implementation of the AES encryption and decryption algorithms.
- **rsa_test.py**: Contains test cases to run the AES functions and verify their functionality.

## Prerequisites

- Python version 3.12.6 or later.

## How to Run

1. Open a terminal window.
2. Navigate to the project directory using the `cd` command.
3. Run the following command to execute the test script:

    ```bash
    python rsa_test.py
    ```

4. Follow the script's prompts:
   - Enter `"y"` or `"n"` when asked: `Do you want to generate new public and private keys?`
   - Enter `"e"` for encryption or `"d"` for decryption when prompted: `Would you like to encrypt or decrypt?`
   - Enter the data you wish to encrypt when prompted: `What would you like to encrypt? or What would you like to decrypt?`
   - Enter `"y"` or `"n"` for: `Do you want to encrypt using your own public key?`
   - If you choose `"n"`, provide the name of the file containing the public key when asked: `Enter the file name that stores the public key`.
   - The script will then proceed with: `Encrypting... or Decrypting...`

