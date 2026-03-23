package com.bangtv.pgptool.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

/**
 * Shared I/O helpers used across the project.
 */
public final class IOUtils {

    private IOUtils() { }

    /**
     * Read all bytes from a file.
     *
     * @param path file to read
     * @return raw byte array
     * @throws IOException if the file cannot be read
     */
    public static byte[] readAllBytes(Path path) throws IOException {
        return Files.readAllBytes(path);
    }

    /**
     * Read all bytes from a file and return them as a String decoded with UTF-8.
     *
     * @param path file to read
     * @return file contents as a string
     * @throws IOException if the file cannot be read
     */
    public static String readString(Path path) throws IOException {
        return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    }

    /**
     * Write a byte array to a file, replacing it if it already exists.
     *
     * @param path  destination file
     * @param bytes data to write
     * @throws IOException on write failure
     */
    public static void writeBytes(Path path, byte[] bytes) throws IOException {
        Files.write(path, bytes,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
    }

    /**
     * Write a String to a file using UTF-8, replacing it if it already exists.
     *
     * @param path     destination file
     * @param content  text to write
     * @throws IOException on write failure
     */
    public static void writeString(Path path, String content) throws IOException {
        Files.write(path, content.getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
    }

    /**
     * Delete a file if it exists. Never throws.
     *
     * @param path file to delete
     */
    public static void deleteIfExists(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) { }
    }

    /**
     * Ensure the directory containing this path exists (and all parents).
     *
     * @param path file or directory path
     * @throws IOException if the directories cannot be created
     */
    public static void ensureParentExists(Path path) throws IOException {
        Path parent = path.getParent();
        if (parent != null && !Files.exists(parent)) {
            Files.createDirectories(parent);
        }
    }

    /**
     * Return the file name (last path segment) as a plain String.
     *
     * @param path file path
     * @return file name without any directory prefix
     */
    public static String fileName(Path path) {
        return path.getFileName().toString();
    }
}
