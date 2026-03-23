package com.bangtv.pgptool.core;

import com.bangtv.pgptool.key.KeyManager;
import com.bangtv.pgptool.util.IOUtils;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.nio.file.Path;
import java.security.NoSuchProviderException;

/**
 * Decrypts an ASCII-armored OpenPGP message (.asc) that was created by
 * {@link PgpEncryptor} or any RFC-4880-compliant tool (GnuPG, Kleopatra).
 *
 * <p>Decryption pipeline (outside → inside):
 * <pre>
 * PGPUtil.getDecoderStream()  → strips .asc armor
 *   └─ JcaPGPObjectFactory    → parses top-level OpenPGP packets
 *        └─ PGPEncryptedDataList → encrypted data + integrity (MDC) packet
 *             └─ PGPPublicKeyEncryptedData → decrypts session key
 *                  └─ PGPCompressedData / PGPLiteralData → original bytes
 * </pre>
 */
public class PgpDecryptor {

    /**
     * Decrypt an OpenPGP message and write the recovered plaintext to a file.
     *
     * @param encryptedFile  the input .asc (or binary .pgp) encrypted file
     * @param outputFile     destination file for the decrypted plaintext
     * @param secretKeyFile  ASCII-armored secret key ring (.asc)
     * @param passPhrase     UTF-8 passphrase protecting the secret key
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    public void decrypt(File encryptedFile, File outputFile,
                        File secretKeyFile, String passPhrase)
            throws IOException, PGPException, NoSuchProviderException {

        IOUtils.ensureParentExists(outputFile.toPath());
        IOUtils.deleteIfExists(outputFile.toPath());

        FileInputStream      fis     = null;
        BufferedInputStream  bufIn   = null;
        InputStream          decoder = null;

        try {
            // ── 1.  Open the armored stream ────────────────────────────────────
            fis     = new FileInputStream(encryptedFile);
            bufIn   = new BufferedInputStream(fis);
            decoder = PGPUtil.getDecoderStream(bufIn);
            JcaPGPObjectFactory objFact = new JcaPGPObjectFactory(decoder);

            // ── 2.  Find the PGPEncryptedDataList ──────────────────────────────
            PGPEncryptedDataList encDataList = findEncryptedDataList(objFact);
            if (encDataList == null) {
                throw new PGPException(
                        "No encrypted data found in: " + encryptedFile.getName());
            }

            // ── 3.  Load secret key and extract the raw private key ───────────
            PGPSecretKey  secretKey = KeyManager.loadSecretKey(secretKeyFile);
            PGPPrivateKey privKey   = KeyManager.extractPrivateKey(secretKey, passPhrase);

            // ── 4.  Find the encrypted-data object that belongs to our key ─────
            PGPPublicKeyEncryptedData encData = null;
            for (PGPEncryptedData ed : encDataList) {
                if (ed instanceof PGPPublicKeyEncryptedData) {
                    PGPPublicKeyEncryptedData pked = (PGPPublicKeyEncryptedData) ed;
                    if (pked.getKeyID() == secretKey.getKeyID()) {
                        encData = pked;
                        break;
                    }
                }
            }

            if (encData == null) {
                throw new PGPException(
                        "No matching encryption key found for this message. "
                        + "Key ID 0x" + Long.toHexString(secretKey.getKeyID()).toUpperCase()
                        + " does not match any recipient in the message.");
            }

            // ── 5.  Decrypt the session key and get the plaintext stream ──────
            PublicKeyDataDecryptorFactory decryptorFactory =
                    new JcePublicKeyDataDecryptorFactoryBuilder()
                            .setProvider("BC")
                            .build(privKey);

            InputStream plainStream = encData.getDataStream(decryptorFactory);

            // ── 6.  Parse the decrypted content (may be compressed) ────────────
            JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(plainStream);
            Object              firstObj  = plainFact.nextObject();

            PGPLiteralData litData = null;

            if (firstObj instanceof PGPCompressedData) {
                // Decompress then read the literal data packet inside.
                PGPCompressedData    compData  = (PGPCompressedData) firstObj;
                JcaPGPObjectFactory decompFact = new JcaPGPObjectFactory(
                        compData.getDataStream());
                Object decompObj = decompFact.nextObject();
                if (decompObj instanceof PGPLiteralData) {
                    litData = (PGPLiteralData) decompObj;
                } else {
                    throw new PGPException(
                            "Unexpected compressed packet type: "
                            + (decompObj == null ? "null" : decompObj.getClass().getSimpleName()));
                }
            } else if (firstObj instanceof PGPLiteralData) {
                litData = (PGPLiteralData) firstObj;
            } else {
                throw new PGPException(
                        "Unexpected packet type after decryption: "
                        + (firstObj == null ? "null" : firstObj.getClass().getSimpleName()));
            }

            // ── 7.  Read the literal data and write to output file ────────────
            String recoveredName = litData.getFileName();
            long   recoveredTime = litData.getModificationTime() == null
                    ? System.currentTimeMillis()
                    : litData.getModificationTime().getTime();

            // PGPLiteralData has getInputStream(), not getLiteralData()
            InputStream dataIn = litData.getInputStream();

            // Read all available bytes (the literal data stream has a known length
            // in the packet header; we read until EOF).
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int    n;
            while ((n = dataIn.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
            byte[] content = baos.toByteArray();

            IOUtils.writeBytes(outputFile.toPath(), content);
            java.nio.file.Files.setLastModifiedTime(
                    outputFile.toPath(),
                    java.nio.file.attribute.FileTime.fromMillis(recoveredTime));

            // ── 8.  Verify the MDC integrity check ─────────────────────────────
            if (encData.isIntegrityProtected() && !encData.verify()) {
                throw new PGPException(
                        "MDC integrity check FAILED — the message may have been tampered with.");
            }

            System.out.println("[PgpDecryptor] Decrypted  \""
                    + encryptedFile.getName() + "\"  →  \"" + outputFile.getName() + "\"");
            System.out.println("                original filename: " + recoveredName);

        } finally {
            closeQuietly(decoder);
            closeQuietly(bufIn);
            closeQuietly(fis);
        }
    }

    /**
     * Walk the top-level objects from the PGP factory until we find the
     * {@link PGPEncryptedDataList}.
     */
    private static PGPEncryptedDataList findEncryptedDataList(JcaPGPObjectFactory factory)
            throws IOException {
        Object obj = factory.nextObject();
        while (obj != null) {
            if (obj instanceof PGPEncryptedDataList) {
                return (PGPEncryptedDataList) obj;
            }
            // GnuPG may emit a One-Pass-Signature packet before the encrypted-data
            // list when the message is also signed; skip it and keep looking.
            obj = factory.nextObject();
        }
        return null;
    }

    /** Close a Closeable in a way that never throws. */
    private static void closeQuietly(Closeable c) {
        if (c != null) {
            try { c.close(); } catch (IOException ignored) { }
        }
    }
}
