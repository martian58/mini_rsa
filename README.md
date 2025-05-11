
---

# 🔐 Mini-RSA

A minimal RSA implementation in Rust for generating keys, encrypting files, and decrypting them using command-line interface. Ideal for educational purposes, learning cryptographic concepts, or lightweight encryption tasks.

---

## 🚀 Features

* Generate RSA key pairs using random two-digit primes
* Save and load public/private keys in readable format
* Encrypt and decrypt **binary files** using RSA
* Modular CLI interface with [`clap`](https://docs.rs/clap)
* Educational and compact implementation

---

## 🛠️ Installation

1. **Clone the repository:**

```bash
git clone https://github.com/martian58/mini_rsa.git
cd mini-rsa
```

2. **Build the project:**

```bash
cargo build --release
```

3. **Run the CLI:**

```bash
./target/release/mini_rsa --help
```
Or use the prcompiled binaries
```bash
mini_rsa-win_v1.0.exe
mini_rsa_v1.0-x86_64-linux 
```

---

## 📦 Usage

### 🔑 Generate Keys

```bash
./mini_rsa generate --name mykey
```

Generates:

* `mykey.pub`: Public key
* `mykey`: Private key

---

### 🔒 Encrypt a File

```bash
./mini_rsa encrypt --input secret.txt --output secret.enc --key mykey.pub
```

> `secret.txt` → `secret.enc`

---

### 🔓 Decrypt a File

```bash
./mini_rsa decrypt --input secret.enc --output revealed.txt --key mykey
```

> `secret.enc` → `revealed.txt`

---

## 🧠 How It Works

* Picks two random two-digit prime numbers.
* Calculates RSA parameters: `n`, `phi`, `e`, and private `d`.
* Uses **modular exponentiation** for both encryption and decryption.
* Keys are saved in a simple custom format for easy inspection.

---

## 🔍 Example

```bash
$ ./mini_rsa generate --name demo
Keys generated: demo.pub (public), demo (private)

$ ./mini_rsa encrypt -i hello.txt -o hello.enc -k demo.pub
File encrypted: hello.enc

$ ./mini_rsa decrypt -i hello.enc -o hello_out.txt -k demo
File decrypted: hello_out.txt
```

---

## 📁 Key File Format

Example `demo.pub`:

```
-----BEGIN RSA PUBLIC KEY-----
65537 3233
-----END RSA PUBLIC KEY-----
```

---

## 📚 Dependencies

* [`clap`](https://crates.io/crates/clap) — Command-line argument parsing
* [`rand`](https://crates.io/crates/rand) — Random number generation

---

## ⚠️ Disclaimer

This implementation is for **educational** purposes only and **not secure** for real-world cryptographic use. It uses small key sizes and lacks padding schemes.

---
