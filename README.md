# Secure File Transfer System (Java – AES + RSA)

A secure end-to-end file transfer system built using **Java TCP Socket Programming**,  
implementing **AES-256-GCM** encryption for file security and **RSA-OAEP** for session key exchange.

This project ensures that files remain **encrypted during transit AND storage**,  
and only decrypt when the user manually chooses to decrypt.

---

##  Core Features

### ✔ End-to-End Encryption (E2EE)
- File encrypted on **client side** using **AES-256-GCM**
- Encrypted bytes travel over TCP socket
- Server stores encrypted file as `.enc`
- Decryption happens **only when user clicks “Decrypt File”** (manual decrypt)

### ✔ Secure Key Exchange (RSA)
- Server generates RSA-2048 key pair
- Server sends **public key** to client
- Client encrypts AES session key using RSA-OAEP
- Server securely unwraps the session key

### ✔ Secure AES Encryption
- AES-256 key generated per session
- AES-GCM mode ensures:
    - Confidentiality
    - Integrity
    - Authentication

### ✔ GUI Interfaces
- **Client GUI**
    - Select file
    - Start secure transfer
    - Shows progress and logs

- **Server GUI**
    - Shows incoming connection
    - Saves encrypted file
    - Manual Decrypt button
    - Logs transfer events

---
