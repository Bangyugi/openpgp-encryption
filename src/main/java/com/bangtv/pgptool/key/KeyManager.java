package com.bangtv.pgptool.key;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.*;
import java.security.NoSuchProviderException;
import java.util.Iterator;

/**
 * Loads and manages OpenPGP public and secret keys from armored (.asc) files.
 *
 * <p>When parsing a key ring exported from GnuPG/Kleopatra, the ring typically
 * contains one Master Key (usage: certify/sign) and one Sub-Key (usage: encrypt).
 * This class always returns the <em>encryption sub-key</em> — not the first key
 * in the ring — to ensure compatibility with GnuPG.</p>
 */
public class KeyManager {

    // ─────────────────────────────────────────────────────────────────────────
    //  Public-key loading
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Load the <em>encryption sub-key</em> from an armored public-key file.
     *
     * <p>The method walks through every key ring in the file and then through
     * every key inside each ring, returning the first key for which
     * {@link PGPPublicKey#isEncryptionKey()} returns {@code true}.</p>
     *
     * @param publicKeyFile an ASCII-armored .asc file containing the public key(s)
     * @return the encryption-capable {@link PGPPublicKey}
     * @throws PGPException
     * @throws FileNotFoundException   if the file does not exist
     * @throws IllegalArgumentException if no encryption key is found
     */
    public static PGPPublicKey loadPublicKey(File publicKeyFile)
            throws PGPException, FileNotFoundException, NoSuchProviderException {

        if (!publicKeyFile.exists()) {
            throw new FileNotFoundException("Public key file not found: " + publicKeyFile);
        }

        try (InputStream fis = new BufferedInputStream(new FileInputStream(publicKeyFile))) {

            // PGPUtil.getDecoderStream() automatically detects and strips the
            // ASCII armor headers/footers, returning a raw binary stream.
            InputStream         decoder    = PGPUtil.getDecoderStream(fis);
            JcaPGPObjectFactory objFactory = new JcaPGPObjectFactory(decoder);

            PGPPublicKey foundKey = null;

            Object obj = objFactory.nextObject();
            while (obj != null && foundKey == null) {
                if (obj instanceof PGPPublicKeyRing) {
                    PGPPublicKeyRing keyRing = (PGPPublicKeyRing) obj;

                    Iterator<PGPPublicKey> it = keyRing.getPublicKeys();
                    while (it.hasNext()) {
                        PGPPublicKey key = it.next();

                        // CRITICAL: GnuPG/Kleopatra rings contain BOTH a certification
                        // master key and an encryption sub-key. We MUST filter by this
                        // predicate or Kleopatra may silently fail to decrypt.
                        if (key.isEncryptionKey()) {
                            foundKey = key;
                            break;
                        }
                    }
                }
                obj = objFactory.nextObject();
            }

            if (foundKey == null) {
                throw new IllegalArgumentException(
                        "No encryption-capable sub-key found in: " + publicKeyFile.getAbsolutePath()
                        + "\n  Ensure you exported the correct key and that it has an Encryption capability.");
            }

            System.out.println("[KeyManager] Loaded encryption key  0x"
                    + Long.toHexString(foundKey.getKeyID()).toUpperCase());

            return foundKey;

        } catch (IOException e) {
            throw new PGPException("Failed to read public key file", e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Secret-key loading
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Load the <em>decryption secret key</em> from an armored secret-key file.
     *
     * @param secretKeyFile an ASCII-armored .asc file containing the secret key(s)
     * @return the {@link PGPSecretKey} whose public component is an encryption key
     * @throws PGPException
     * @throws FileNotFoundException
     */
    public static PGPSecretKey loadSecretKey(File secretKeyFile)
            throws PGPException, FileNotFoundException, NoSuchProviderException {

        if (!secretKeyFile.exists()) {
            throw new FileNotFoundException("Secret key file not found: " + secretKeyFile);
        }

        try (InputStream fis = new BufferedInputStream(new FileInputStream(secretKeyFile))) {

            InputStream         decoder    = PGPUtil.getDecoderStream(fis);
            JcaPGPObjectFactory objFactory = new JcaPGPObjectFactory(decoder);

            PGPSecretKey foundKey = null;

            Object obj = objFactory.nextObject();
            while (obj != null && foundKey == null) {
                if (obj instanceof PGPSecretKeyRing) {
                    PGPSecretKeyRing keyRing = (PGPSecretKeyRing) obj;

                    Iterator<PGPSecretKey> it = keyRing.getSecretKeys();
                    while (it.hasNext()) {
                        PGPSecretKey key = it.next();

                        // Must be the encryption-capable key to decrypt what we encrypted.
                        if (key.getPublicKey().isEncryptionKey()) {
                            foundKey = key;
                            break;
                        }
                    }
                }
                obj = objFactory.nextObject();
            }

            if (foundKey == null) {
                throw new IllegalArgumentException(
                        "No encryption-capable secret key found in: " + secretKeyFile.getAbsolutePath());
            }

            System.out.println("[KeyManager] Loaded secret key  0x"
                    + Long.toHexString(foundKey.getKeyID()).toUpperCase());

            return foundKey;

        } catch (IOException e) {
            throw new PGPException("Failed to read secret key file", e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Key decryption (secret-key → PGPPrivateKey)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Extract the {@link PGPPrivateKey} from a secret key using a passphrase.
     *
     * <p>Usage:
     * <pre>
     * PGPSecretKey    secKey = KeyManager.loadSecretKey(secFile);
     * PGPPrivateKey   privKey = KeyManager.extractPrivateKey(secKey, "mypassphrase");
     * </pre>
     *
     * @param secretKey the secret key (with its public portion being an encryption key)
     * @param passPhrase UTF-8 passphrase protecting the secret key
     * @return the raw private key component, ready for use with {@link PGPPublicKeyEncryptedData}
     * @throws PGPException if the passphrase is wrong or the key is malformed
     */
    public static PGPPrivateKey extractPrivateKey(PGPSecretKey secretKey, String passPhrase)
            throws PGPException {

        // JcePBESecretKeyDecryptorBuilder (no-arg constructor) builds a
        // PBESecretKeyDecryptor that handles the S2K (string-to-key) derivation.
        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder()
                .setProvider("BC")
                .build(passPhrase.toCharArray());

        return secretKey.extractPrivateKey(decryptor);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Utilities
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Format a PGP key fingerprint as an upper-case hex string with spaces
     * every 4 characters (e.g. "4A3B B2F1 8D3C…").
     */
    public static String fingerprint(PGPPublicKey key) {
        byte[] fp = key.getFingerprint();
        StringBuilder sb = new StringBuilder(fp.length * 3);
        for (int i = 0; i < fp.length; i++) {
            if (i > 0 && i % 2 == 0) {
                if (i % 4 == 0) sb.append(' ');
                else            sb.append(' ');
            }
            sb.append(String.format("%02X", fp[i]));
        }
        return sb.toString();
    }
}
