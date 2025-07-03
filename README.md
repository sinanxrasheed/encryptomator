# Encryptomator

Encryptomator is a simple, user-friendly desktop application for creating and managing encrypted vaults (folders) to securely store your files. Built with Electron, it uses modern cryptography standards to keep your data private and protected on your computer.

---

## Features

- **Create Encrypted Vaults:** Protect folders with a strong password.
- **Encrypt Files:** Securely encrypt files and store them in your vault.
- **Decrypt Files:** Restore encrypted files to their original form.
- **Reveal/Lock Vault:** Temporarily decrypt the entire vault for browsing, then lock it again.
- **Strong Security:** Uses Argon2id for password hashing and AES-256-GCM for file encryption.

---

## Installation

1. **Clone or Download the Repository**
   ```sh
   git clone <repository-url>
   cd encryptomator-main
   ```
   Or download and extract the ZIP, then open the folder in your terminal.

2. **Install Dependencies**
   ```sh
   npm install
   ```

---

## Usage

1. **Start the Application**
   ```sh
   npm start
   ```
   This will launch the Encryptomator desktop app.

2. **Create a New Vault**
   - Click `Create New Vault`.
   - Choose a name and location for your vault.
   - Set a strong password and confirm it.
   - Click `Finalize Vault` to create your encrypted vault.

3. **Encrypt Files**
   - Click `Select File to Encrypt` and choose a file.
   - Enter your vault password.
   - Click `Encrypt File` to add the file to your vault.

4. **Decrypt Files**
   - Click `Select File to Decrypt` and choose an encrypted file from your vault.
   - Click `Select Output Directory` to choose where to save the decrypted file.
   - Enter your vault password.
   - Click `Decrypt File` to restore the file.

5. **Reveal/Lock Vault**
   - Click `Reveal Disk` to temporarily decrypt all files in the vault to a folder for browsing.
   - When done, click `Lock Disk` to re-encrypt and remove the temporary folder.

6. **Open Existing Vault**
   - Click `Open Existing Vault` and select your vault folder.
   - Enter your password to unlock and manage files.

---

## Security Notes

- **Encryption:** Files are encrypted with AES-256-GCM. Passwords are hashed and keys derived using Argon2id.
- **Metadata Protection:** Vault metadata and file indexes are also encrypted.
- **Password:** Use a strong, unique password. If you forget your password, your data cannot be recovered.

---

## Dependencies

- [Electron](https://www.electronjs.org/)
- [argon2](https://www.npmjs.com/package/argon2)
- [crypto-js](https://www.npmjs.com/package/crypto-js)

---

## Disclaimer

Encryptomator is provided as-is, without warranty. Always back up your data and test the application with non-critical files before using it for important information.

---

## Inspiration

This application was created as a learning project inspired by [Cryptomator](https://cryptomator.org/), an open-source client-side encryption solution for your cloud files. Encryptomator is not affiliated with Cryptomator, but aims to provide similar vault-based encryption concepts in a simplified desktop app. 
