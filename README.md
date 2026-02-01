# SecureTextChat

Here is a complete, updated `README.md` tailored specifically for your new **GUI version** of SecureChat. It includes instructions for the new interface and specific troubleshooting steps for the "Connection Refused" error you encountered.

You can save this as `README.md` in your project folder.

---

# SecureChat GUI: Encrypted P2P Messaging

**SecureChat GUI** is a Python-based encrypted messaging application that provides a secure, peer-to-peer communication channel with a user-friendly Graphical User Interface (GUI).

It leverages advanced cryptographic standards—**Diffie-Hellman Key Exchange**, **AES-256 Encryption**, and **HMAC Authentication**—to ensure that messages remain confidential and tamper-proof. The application now features a responsive `tkinter` interface with multi-threading to handle connections without freezing.

## 📸 Interface

*(Replace `screenshot.jpg` with the actual path to your screenshot)*

## ✨ Features

* **Graphical User Interface:** Easy-to-use window for configuration, status monitoring, and messaging.
* **Diffie-Hellman Key Exchange:** Securely generates shared keys between two parties without transmitting private keys over the network.
* **AES-256 Encryption (CBC Mode):** Messages are encrypted using the shared DH key with unique Initialization Vectors (IVs) for every message.
* **Mutual Authentication:** Uses a Challenge-Response mechanism (HMAC-SHA256) to ensure both the sender and receiver know the shared password before exchanging keys.
* **Integrity Checks:**
* **CRC32:** Detects data corruption during transmission.
* **HMAC Logging:** Local logs (`logging.txt`, `clientlogging.txt`) are signed to prevent tampering.


* **Multi-threaded Architecture:** Background threads handle network listening and message sending, keeping the GUI responsive.

## 🛠️ Installation

### Prerequisites

* Python 3.x
* `tkinter` (Usually included with standard Python installations)

### Dependencies

Install the required cryptographic libraries:

```bash
pip install pycryptodome cryptography

```

## 🚀 How to Run (Local Simulation)

Since this is a Peer-to-Peer (P2P) application, you need **two running instances** to simulate a chat (one acts as the receiver, one as the sender).

### Step 1: Start Two Instances

Open two separate terminal windows. In each one, run:

```bash
python gui_chat.py

```

### Step 2: Configure the Receiver (Window A)

1. **My Port:** Enter `12345`
2. **My Password:** Enter your shared password (e.g., `password1`).
3. Click **Start Server**.
4. *Status should show: "Listening on port 12345..."*

### Step 3: Configure the Sender (Window B)

1. **My Port:** Enter `12346` (Must be different from Window A if on the same machine).
2. **My Password:** Enter `password1` (Must act as a server too for mutual auth).
3. Click **Start Server**.

### Step 4: Send a Message

In **Window B (Sender)**:

1. **Target IP:** `127.0.0.1` (Localhost)
2. **Target Port:** `12345` (The port Window A is listening on).
3. **Message:** Type your text.
4. Click **SEND**.

---

## 🔒 Security Architecture

1. **Handshake:** Connection initiates with a "Hello". The server provides a Diffie-Hellman public key.
2. **Key Derivation:** Both parties generate a shared secret using HKDF (HMAC-based Key Derivation Function).
3. **Challenge-Response:**
* The server sends a random nonce (Challenge).
* The client must return the SHA256 hash of `Challenge + Password`.
* The server verifies this to allow the connection.


4. **Encryption:** The message body is padded and encrypted via AES-CBC.
5. **Logging:** Incoming messages are saved to `logging.txt` and outgoing to `clientlogging.txt`, with HMAC signatures appended to every line.

## ❓ Troubleshooting

### Error: `[Send Error] [Errno 61] Connection refused`

**Cause:** You are trying to send a message to a port that is not open.
**Solution:**

1. Check the **Target Port** in your sender window (e.g., 12346).
2. Ensure the **Receiver Window** has "My Port" set to 12346.
3. **Crucial:** Make sure the Receiver has clicked the **Start Server** button. If the server isn't running, the connection will be refused.

### Error: `Authentication Failed`

**Cause:** The password entered in the Client does not match the password expected by the Server.
**Solution:** Ensure both parties have agreed upon and entered the exact same password in the "My Password" field.

---

## 📂 File Structure

* `gui_chat.py`: The main application code containing GUI and Crypto logic.
* `logging.txt`: Auto-generated log of received messages.
* `clientlogging.txt`: Auto-generated log of sent messages.
* `users.json`: (Optional) User directory for loading presets.

### Optional JSON Format

If you wish to load users from a file instead of typing manually:

```json
[
    {
        "username": "user1",
        "password": "password1",
        "ip": "127.0.0.1",
        "port": 12345
    }
]

```
