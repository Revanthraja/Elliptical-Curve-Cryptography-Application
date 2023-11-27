# Elliptical Curve Cryptography Application

This application is built using Python and PyQt5 to perform Elliptical Curve Cryptography (ECC) operations. It utilizes the `Crypto` library for AES encryption and decryption, along with the `eclib` library for ECC operations.

## Features

- **EC Diffie Hellman**: Implements the Elliptic Curve Diffie-Hellman (ECDH) key exchange algorithm.
- **AES Encryption/Decryption**: Uses AES encryption to encode and decode text based on the exchanged keys from ECDH.
- **Graphical User Interface (GUI)**: Utilizes PyQt5 for a user-friendly interface to input ECC parameters and perform encryption/decryption.

## Installation

### Prerequisites

- Python 3.x
- PyQt5 (`pip install PyQt5`)
- pycryptodome or pycryptodomex (`pip install pycryptodome` or `pip install pycryptodomex`)
- eclib library (Add installation instructions if required)

### Setup

1. Clone this repository.
2. Install the necessary dependencies using `pip`:
   ```bash
   pip install PyQt5 pycryptodome  # Add other dependencies if required
