package com.bangtv.pgptool.core;

import com.bangtv.pgptool.util.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.security.SecureRandom;
import java.util.Date;

/**
 * Encrypts a file to an ASCII-armored OpenPGP message (.asc) that is fully
 * compatible with GnuPG, Kleopatra, and other RFC-4880-compliant tools.
 *
 * <p>Encryption pipeline (outside → inside):
 * <pre>
 * FileOutputStream
 *   └─ ArmoredOutputStream          → .asc wrapper
 *        └─ PGPEncryptedDataGenerator → AES-256 + MDC integrity
 *             └─ PGPCompressedDataGenerator → ZIP compression
 *                  └─ PGPLiteralDataGenerator → original filename / mod time
 *                       └─ openOutputStream() → bytes written here
 * </pre>
 *
 * <p><b>Critical resource-management note:</b> The three Bouncy Castle generator
 * classes ({@link PGPEncryptedDataGenerator}, {@link PGPCompressedDataGenerator},
 * {@link PGPLiteralDataGenerator}) do <em>not</em> implement
 * {@link AutoCloseable} in BC 1.78.1.  They have a manual {@code close()}
 * method only.  This implementation places them in explicit {@code try} blocks
 * (not try-with-resources) and calls {@code close()} in {@code finally} blocks,
 * guaranteeing that each nested packet is finalised (EOF markers written) in the
 * correct reverse order before the outer {@link ArmoredOutputStream} is flushed.
 * If the generators are not closed, the OpenPGP packets lack EOF markers and
 * Kleopatra reports "Corrupted Data".</p>
 */
public class PgpEncryptor {

    /**
     * Encrypt a file and write the result as an ASCII-armored OpenPGP message.
     *
     * @param plainFile   file to encrypt (name and modification time are preserved)
     * @param outputFile  destination .asc file
     * @param publicKey   encryption-capable public key loaded via {@link com.bangtv.pgptool.key.KeyManager}
     * @throws IOException on file I/O errors
     * @throws PGPException on PGP pipeline errors
     */
    public void encrypt(File plainFile, File outputFile, PGPPublicKey publicKey)
            throws IOException, PGPException {

        IOUtils.ensureParentExists(outputFile.toPath());
        IOUtils.deleteIfExists(outputFile.toPath());

        byte[]   fileBytes = IOUtils.readAllBytes(plainFile.toPath());
        String   fileName  = plainFile.getName();
        long     modTime   = plainFile.lastModified();

        FileOutputStream         fos      = null;
        ArmoredOutputStream      armored  = null;
        PGPEncryptedDataGenerator encGen  = null;
        OutputStream             encOut   = null;
        PGPCompressedDataGenerator compGen = null;
        OutputStream             compOut  = null;
        PGPLiteralDataGenerator  litGen   = null;
        OutputStream             litOut   = null;

        try {
            // 1.  FileOutputStream — lowest level, holds the file handle.
            fos = new FileOutputStream(outputFile);

            // 2.  ArmoredOutputStream — wraps binary output as ASCII armor (.asc).
            armored = new ArmoredOutputStream(fos);

            // 3.  PGPEncryptedDataGenerator — encrypts the session key with the
            //     public key; encrypts data with AES-256.
            //     setWithIntegrityPacket(true) emits an MDC packet so GnuPG can
            //     detect post-encryption tampering (recommended for all modern use).
            encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC"));

            // Add the public-key encryption method (RSA, ElGamal, etc. — automatically
            // selected based on the key algorithm).
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey)
                    .setProvider("BC"));

            // Open the encrypted-data stream; pass estimated output size as hint.
            encOut = encGen.open(armored, fileBytes.length);

            // 4.  PGPCompressedDataGenerator — wraps the literal data in a ZIP
            //     compression packet (inside the encrypted packet).
            compGen = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
            compOut = compGen.open(encOut);

            // 5.  PGPLiteralDataGenerator — stores the original filename, format,
            //     modification time, and file length.  Kleopatra requires these
            //     metadata fields; without them it may show "no metadata" warnings.
            litGen = new PGPLiteralDataGenerator();
            litOut = litGen.open(
                    compOut,
                    PGPLiteralData.BINARY,
                    fileName,
                    fileBytes.length,
                    new Date(modTime));

            // 6.  Write plaintext — data flows through the entire pipeline:
            //     litOut → PGPLiteralDataGenerator → ZIP → AES-256 → armor → file
            litOut.write(fileBytes);

        } finally {
            // Close in REVERSE order (LIFO) so each layer finalises its packet
            // before the layer above it is closed.
            closeQuietly(litOut);
            closeGenerator(litGen);    // PGPLiteralDataGenerator.close()
            closeQuietly(compOut);
            closeGenerator(compGen);   // PGPCompressedDataGenerator.close()
            closeQuietly(encOut);
            closeGenerator(encGen);    // PGPEncryptedDataGenerator.close()
            closeQuietly(armored);
            closeQuietly(fos);
        }

        System.out.println("[PgpEncryptor] Encrypted  \""
                + fileName + "\"  →  \"" + outputFile.getName() + "\"");
    }

    /**
     * Close an {@link OutputStream} in a way that never throws.
     * Used for the byte-stream resources (fos, armored, encOut, compOut, litOut).
     */
    private static void closeQuietly(OutputStream os) {
        if (os != null) {
            try { os.close(); } catch (IOException ignored) { }
        }
    }

    /**
     * Close a BC generator (which implements {@link org.bouncycastle.util.StreamGenerator})
     * in a way that never throws.  The generators do not implement AutoCloseable
     * in BC 1.78.1; they expose a no-arg {@code close()} method inherited from
     * {@code StreamGenerator}.
     */
    private static void closeGenerator(Object generator) {
        if (generator != null) {
            try {
                generator.getClass().getMethod("close").invoke(generator);
            } catch (Exception ignored) { }
        }
    }
}
