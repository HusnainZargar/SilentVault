# SilentVault - Secure Password Manager

A console-based **C++ password manager** that securely stores and manages credentials using **XChaCha20-Poly1305** encryption and **Argon2id** key derivation, designed for **Unix-like systems** (Linux/macOS).

---

## Features

- **Secure Storage**: Encrypts credentials with XChaCha20-Poly1305, using unique salts and nonces per entry.
- **Tamper Detection**: Verifies integrity with a `VERIFY-ME` tag, marking tampered entries as corrupted.
- **Key Derivation**: Uses Argon2id (memory-hard) to derive keys from the master password.
- **Password Management**:
  - Add, view, edit, and delete password entries.
  - Change master password with full data re-encryption.
- **Secure Input**: Hides master password input via terminal echo suppression.
- **Memory Safety**: Wipes sensitive data (passwords, keys) using `sodium_memzero`.
- **Atomic Saves**: Ensures file integrity with temporary files and atomic renames.
- **User Interface**: Menu-driven console with color-coded output and security tips.
- **Master Password Policy**: Enforces 12+ characters with uppercase, lowercase, digits, and special characters.

---
## Installation

### Prerequisites
- **OS**: Linux or macOS (requires `$HOME` environment variable).
- **Compiler**: `g++` with C++11 or later.
- **Dependencies**: `libsodium`, `libargon2`.

---

### Steps

**1. Install dependencies**

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install libsodium-dev libargon2-dev
```
**MacOS:**
```bash
brew install libsodium argon2
```
**2. Clone the repository**

```bash
git clone https://github.com/HusnainZargar/SilentVault.git
cd silentvault
```

**3. Compile**

```bash
g++ -o SilentVault SilentVault.cpp -lsodium -largon2
```

**4. Run**

```bash
./SilentVault
```

---

## Security

- **Encryption**: XChaCha20-Poly1305 ensures confidentiality and integrity.
- **Key Derivation**: Argon2id (t_cost=4, m_cost=64MB, parallelism=4) resists brute-force.
- **Tamper Detection**: Entries failing decryption or tag check are marked corrupted.
- **File Safety**: Atomic saves and 0600 permissions prevent corruption and unauthorized access.
- **Memory Protection**: Sensitive data wiped with sodium_memzero.
- **Warnings**:
  - Do not edit system.enc manually; tampering causes data loss or corruption.
  - Back up system.enc securely; no recovery for lost master passwords.
  - Use in trusted environments to avoid shoulder-surfing.

---

## License
MIT License. See the LICENSE file for details.

---

## Contact

- **Author**: Muhammad Husnain Zargar
- **LinkedIn**: [Profile](https://www.linkedin.com/in/muhammad-husnain-z995/)
- **Email**: info@hackwithhusnain.com
- **GitHub Issues**: Report bugs/features
