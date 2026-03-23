package com.bangtv.pgptool;

import com.bangtv.pgptool.core.PgpDecryptor;
import com.bangtv.pgptool.core.PgpEncryptor;
import com.bangtv.pgptool.key.KeyManager;
import com.bangtv.pgptool.util.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPPublicKey;

import java.io.File;
import java.nio.file.Path;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Entry point for the OpenPGP file encryption / decryption tool.
 *
 * <p>Registers Bouncy Castle as the JCE security provider, then runs an
 * end-to-end encrypt cycle using the key files found in the {@code keys/}
 * directory.</p>
 *
 * <p>Expected layout inside {@code keys/}:
 * <ul>
 *   <li>{@code public_key.asc}      — public encryption key exported from Kleopatra</li>
 *   <li>{@code secret.txt}          — plaintext file to encrypt</li>
 *   <li>{@code encrypted_secret.asc} — output produced by this program</li>
 *   <li>{@code secret_key.asc}      — secret key for decryption testing (optional)</li>
 * </ul>
 */
public class MainApp {

    /** Relative path to the directory holding test keys and files. */
    private static final String KEYS_DIR = "keys";

    public static void main(String[] args) {
        printHeader();

        // ── 1. Register Bouncy Castle as the JCE provider ──────────────────────
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
            System.out.println("[MainApp] Bouncy Castle provider registered.");
        } else {
            System.out.println("[MainApp] Bouncy Castle provider already present.");
        }

        try {
            Path keysDir        = new File(KEYS_DIR).toPath().toAbsolutePath().normalize();
            File publicKeyFile  = keysDir.resolve("public_key.asc").toFile();
            File secretFile     = keysDir.resolve("secret.txt").toFile();
            File encryptedFile  = keysDir.resolve("encrypted_secret.asc").toFile();
            File decryptedFile  = keysDir.resolve("decrypted_secret.txt").toFile();
            File secretKeyFile  = keysDir.resolve("secret_key.asc").toFile(); // optional

            // ── 2. Validate input files ───────────────────────────────────────
            validateFile("Public key", publicKeyFile);
            validateFile("Plaintext",  secretFile);

            // ── 3. Load the encryption public key ─────────────────────────────
            // KeyManager automatically finds the encryption sub-key
            // (skips the certification master key).
            PGPPublicKey publicKey = KeyManager.loadPublicKey(publicKeyFile);
            System.out.println("[MainApp] Public key fingerprint: "
                    + KeyManager.fingerprint(publicKey));

            // ── 4. Encrypt ─────────────────────────────────────────────────────
            PgpEncryptor encryptor = new PgpEncryptor();
            encryptor.encrypt(secretFile, encryptedFile, publicKey);
            System.out.println("[MainApp] Encryption complete → "
                    + encryptedFile.getAbsolutePath());

            // ── 5. Decrypt (optional — only if secret key is present) ─────────
            if (secretKeyFile.exists()) {
                System.out.println(
                        "[MainApp] secret_key.asc found — running decryption test…");
                PgpDecryptor decryptor = new PgpDecryptor();
                System.out.print("  Passphrase for secret key: ");
                String passphrase = readPassphrase();

                decryptor.decrypt(encryptedFile, decryptedFile, secretKeyFile, passphrase);

                // ── 6. Verify round-trip ───────────────────────────────────────
                String original   = IOUtils.readString(secretFile.toPath());
                String recovered  = IOUtils.readString(decryptedFile.toPath());

                if (original.equals(recovered)) {
                    System.out.println(
                            "[MainApp] ✓ Round-trip VERIFIED — decrypted content matches original.");
                } else {
                    System.err.println(
                            "[MainApp] ✗ Round-trip FAILED — content mismatch!");
                    System.exit(1);
                }
            } else {
                System.out.println(
                        "[MainApp] secret_key.asc not found — skipping decryption test.");
                System.out.println(
                        "[MainApp] You can test the .asc file with Kleopatra or:");
                System.out.println(
                        "[MainApp]   gpg --decrypt encrypted_secret.asc");
            }

            printSuccess();

        } catch (Exception e) {
            printError(e);
            System.exit(1);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static void validateFile(String label, File file) {
        if (!file.exists() || !file.isFile()) {
            throw new IllegalStateException(
                    label + " file not found: " + file.getAbsolutePath()
                    + "\n  Make sure the file exists in the project " + KEYS_DIR + "/ directory.");
        }
    }

    /** Read a passphrase from stdin without echoing the characters (console-aware). */
    private static String readPassphrase() {
        try {
            char[] chars = System.console().readPassword();
            if (chars != null) {
                return new String(chars);
            }
        } catch (Exception ex) {
            // Fall through to Scanner fallback for IDEs (IntelliJ, Eclipse run tab)
        }
        java.util.Scanner scanner = new java.util.Scanner(System.in);
        try {
            return scanner.nextLine();
        } finally {
            scanner.close();
        }
    }

    private static void printHeader() {
        String line = repeat("=", 60);
        System.out.println();
        System.out.println("+" + line + "+");
        System.out.println("|" + padCenter("OpenPGP File Encryptor  (Java 8 + Bouncy Castle)", 60) + "|");
        System.out.println("+" + line + "+");
        System.out.println();
    }

    private static void printSuccess() {
        String ts = new SimpleDateFormat("HH:mm:ss").format(new Date());
        System.out.println();
        System.out.println("+----------------------------------------------+");
        System.out.println("|  All done  [" + ts + "]                |");
        System.out.println("+----------------------------------------------+");
    }

    private static void printError(Exception e) {
        System.err.println();
        System.err.println("+----------------------------------------------+");
        System.err.println("|  ERROR: " + e.getClass().getSimpleName()
                + padRight("", 36) + "|");
        System.err.println("+----------------------------------------------+");
        System.err.println();
        e.printStackTrace(System.err);
    }

    private static String repeat(String s, int count) {
        StringBuilder sb = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            sb.append(s);
        }
        return sb.toString();
    }

    private static String padCenter(String s, int width) {
        int padding = Math.max(0, width - s.length());
        int leftPad = padding / 2;
        return repeat(" ", leftPad) + s + repeat(" ", padding - leftPad);
    }

    private static String padRight(String s, int n) {
        return String.format("%-" + n + "s", s);
    }
}
