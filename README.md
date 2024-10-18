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

