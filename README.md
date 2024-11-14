# AES File Encryption/Decryption Tool

### Description
A Python tool that allows you to encrypt and decrypt files using AES-256 encryption. This script is useful for securing sensitive files with password-based encryption.

### Features
- **AES-256 Encryption**: Uses a 256-bit AES encryption key for secure file encryption.
- **Password-Derived Key**: Generates an encryption key from a password for added security.
- **Automatic Data Padding**: Pads file data to ensure it meets AES block size requirements.

### Requirements
- Python 3.x
- `cryptography` library

### Installation

1. **Install the required `cryptography` package**:
   ```bash
   pip install cryptography
