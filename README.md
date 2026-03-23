# OpenPGP File Encryptor

Standalone Java 8 application for encrypting (and decrypting) files using OpenPGP public keys, fully compatible with GnuPG and Kleopatra.

## Tech Stack

| Component | Version |
|-----------|---------|
| Java | 8 |
| Bouncy Castle (bcprov) | 1.78.1 |
| Bouncy Castle (bcpg) | 1.78.1 |
| Maven | 3.x |

## Project Structure

```
openpgp-encryption/
├── pom.xml
├── keys/                                ← place your test files here
│   ├── public_key.asc                  ← your Kleopatra public key (REQUIRED)
│   ├── secret.txt                      ← file to encrypt (REQUIRED)
│   ├── secret_key.asc                  ← your secret key (OPTIONAL — for decryption test)
│   ├── encrypted_secret.asc             ← output: encrypted file
│   └── decrypted_secret.txt            ← output: decrypted file (optional)
└── src/main/java/com/bangtv/pgptool/
    ├── MainApp.java                    ← entry point
    ├── core/
    │   ├── PgpEncryptor.java           ← encryption logic
    │   └── PgpDecryptor.java           ← decryption logic
    ├── key/
    │   └── KeyManager.java             ← key parsing & extraction
    └── util/
        └── IOUtils.java               ← I/O helpers
```

## Quick Start

### 1. Prepare Your Files

Create the `keys/` directory and place your files inside:

```
keys/
├── public_key.asc     ← export from Kleopatra: Right-click key → Export → "Export public keys"
└── secret.txt         ← any text file you want to encrypt
```

**To also test decryption**, export your secret key:
```
keys/
└── secret_key.asc     ← export from Kleopatra: Right-click key → Export → "Export secret keys"
```

### 2. Compile

```bash
mvn compile
```

### 3. Run

```bash
mvn exec:java -Dexec.mainClass="com.bangtv.pgptool.MainApp"
```

Or from your IDE (IntelliJ, Eclipse…), just run `MainApp.java`.

### 4. Expected Output

```
+============================================================+
|      OpenPGP File Encryptor  (Java 8 + Bouncy Castle)      |
+============================================================+

[MainApp] Bouncy Castle provider registered.
[KeyManager] Loaded encryption key  0xA1B2C3D4E5F60718
[MainApp] Public key fingerprint: 4A3B B2F1 8D3C ...
[PgpEncryptor] Encrypted  "secret.txt"  →  "encrypted_secret.asc"
[MainApp] Encryption complete → C:\...\keys\encrypted_secret.asc

[MainApp] secret_key.asc found — running decryption test…
  Passphrase for secret key:
[PgpDecryptor] Decrypted  "encrypted_secret.asc"  →  "decrypted_secret.txt"
                original filename: secret.txt
[MainApp] ✓ Round-trip VERIFIED — decrypted content matches original.

+----------------------------------------------+
|  All done  [14:32:05]                        |
+----------------------------------------------+
```

### 5. Verify with Kleopatra

Open `keys/encrypted_secret.asc` in Kleopatra and click **Decrypt/Verify**. You should see the decrypted file content.

---

## How It Works

### Encryption Pipeline

```
FileOutputStream
  └─ ArmoredOutputStream          (.asc / ASCII armor format)
       └─ PGPEncryptedDataGenerator   (AES-256 + MDC integrity)
            └─ PGPCompressedDataGenerator (ZIP compression)
                 └─ PGPLiteralDataGenerator (preserves filename & mod time)
                      └─ OutputStream (plaintext bytes written here)
```

1. **ArmoredOutputStream** — encodes the binary OpenPGP packets as base64 text (`.asc`)
2. **PGPEncryptedDataGenerator** — encrypts the session key with RSA; encrypts the data with AES-256; includes an MDC (Modification Detection Code) packet so GnuPG can detect post-encryption tampering
3. **PGPCompressedDataGenerator** — compresses the literal data packet with ZIP before encryption
4. **PGPLiteralDataGenerator** — stores the original filename, modification time, and format (binary); Kleopatra uses these fields to display the output filename

### Key Parsing (Requirement 1)

GnuPG/Kleopatra key rings always contain at least two keys:

| Key Type | Usage | Filter Used |
|----------|-------|-------------|
| Master Key | Certify / Sign | `key.isEncryptionKey() == false` → **skipped** |
| Encryption Sub-Key | Encrypt / Decrypt | `key.isEncryptionKey() == true` → **selected** |

The code iterates through every key ring, then every key in each ring, and returns only the first key where `isEncryptionKey()` is `true`. This ensures the right key is always used even if the export contains multiple sub-keys.

### Resource Management (Requirement 3)

BC 1.78.1's `PGPEncryptedDataGenerator`, `PGPCompressedDataGenerator`, and `PGPLiteralDataGenerator` do **not** implement `AutoCloseable`. They have a manual `close()` method only. The implementation uses explicit `try / finally` blocks with a `closeGenerator()` helper:

```java
try {
    fos      = new FileOutputStream(outputFile);
    armored  = new ArmoredOutputStream(fos);
    encGen   = new PGPEncryptedDataGenerator(...);
    encOut   = encGen.open(armored, fileBytes.length);
    compGen  = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
    compOut  = compGen.open(encOut);
    litGen   = new PGPLiteralDataGenerator();
    litOut   = litGen.open(compOut, PGPLiteralData.BINARY, fileName, fileBytes.length, new Date(modTime));
    litOut.write(fileBytes);
} finally {
    // Close in REVERSE order (LIFO) so each layer finalises its packet
    // before the layer above it is closed.
    closeQuietly(litOut);
    closeGenerator(litGen);    // writes literal-data EOF marker
    closeQuietly(compOut);
    closeGenerator(compGen);   // writes compressed-data EOF marker
    closeQuietly(encOut);
    closeGenerator(encGen);    // writes encrypted-data EOF marker + MDC
    closeQuietly(armored);     // writes base64 CRC footer
    closeQuietly(fos);
}
```

> **Critical:** If the generators are not explicitly closed, the OpenPGP packets lack EOF markers and Kleopatra/GnuPG will report "Corrupted Data".

---

## API Reference

### `PgpEncryptor.encrypt(plainFile, outputFile, publicKey)`

```java
File plainFile   = new File("keys/secret.txt");
File outputFile  = new File("keys/encrypted_secret.asc");
PGPPublicKey key = KeyManager.loadPublicKey(new File("keys/public_key.asc"));

new PgpEncryptor().encrypt(plainFile, outputFile, key);
```

### `PgpDecryptor.decrypt(encryptedFile, outputFile, secretKeyFile, passphrase)`

```java
new PgpDecryptor().decrypt(
    new File("keys/encrypted_secret.asc"),
    new File("keys/decrypted_secret.txt"),
    new File("keys/secret_key.asc"),
    "your-passphrase"
);
```

### `KeyManager.loadPublicKey(File)`

Loads the first encryption-capable sub-key from an armored `.asc` file.

### `KeyManager.extractPrivateKey(PGPSecretKey, String passphrase)`

Extracts the raw private key from a secret key using a passphrase. Returns a `PGPPrivateKey` suitable for use with `PGPPublicKeyEncryptedData`.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Kleopatra: "Corrupted Data" | Generators not closed | Ensure all three BC generators are closed in `finally` block |
| Kleopatra: "No key found" | Wrong key used | Ensure you exported the **public** key, not secret |
| Decryption fails | Wrong passphrase | Pass the exact passphrase used when creating the key in Kleopatra |
| Decryption fails | Wrong key ring | Ensure `secret_key.asc` is the matching private key for `public_key.asc` |
| No encryption key found | Key has no encryption capability | Re-export the key and ensure it has an Encryption sub-key |
| MDC integrity check failed | Data was tampered with after encryption | The encrypted content was modified; re-encrypt |
