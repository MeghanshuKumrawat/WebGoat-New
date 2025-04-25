package org.owasp.webgoat.lessons.pathtraversal.archive;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.StandardCopyOption;
import lombok.extern.slf4j.Slf4j;

/**
 * Helper class for securely extracting tar archives
 */
@Slf4j
public class TarArchiveHelper {

    /**
     * Extract a tar file to a destination directory with security checks
     * 
     * @param tarFile The tar file to extract
     * @param destinationDir The directory to extract to
     * @throws IOException If an IO error occurs
     */
    public static void extractTarFile(File tarFile, Path destinationDir) throws IOException {
        if (!destinationDir.toFile().exists()) {
            Files.createDirectories(destinationDir);
        }
        
        try (TarArchiveInputStream tarInputStream = 
                new TarArchiveInputStream(new FileInputStream(tarFile))) {
            
            TarArchiveEntry entry;
            while ((entry = tarInputStream.getNextTarEntry()) != null) {
                // Security check: Validate no path traversal attempts
                String entryName = entry.getName();
                if (entryName.contains("..") || entryName.startsWith("/") || entryName.startsWith("\\")) {
                    log.warn("Security warning: Potential path traversal in tar entry: {}", entryName);
                    continue; // Skip this entry
                }
                
                // Create output file path
                Path outputPath = destinationDir.resolve(entryName).normalize();
                
                // Security check: Ensure the output path is inside the destination directory
                if (!outputPath.startsWith(destinationDir)) {
                    log.warn("Security warning: Tar entry would extract outside target directory: {}", entryName);
                    continue; // Skip this entry
                }
                
                // Security check: Check for setuid/setgid bits and warn if present
                if ((entry.getMode() & 0x800) != 0 || (entry.getMode() & 0x400) != 0) {
                    log.warn("Security warning: Tar entry contains setuid/setgid bits: {}", entryName);
                    // Continue processing but clear the setuid/setgid bits
                    entry.setMode(entry.getMode() & 0xFBFF); // Clear the setuid bit
                    entry.setMode(entry.getMode() & 0xF7FF); // Clear the setgid bit
                }
                
                if (entry.isDirectory()) {
                    Files.createDirectories(outputPath);
                } else {
                    // Ensure parent directories exist
                    Files.createDirectories(outputPath.getParent());
                    
                    // Extract file
                    try (InputStream is = tarInputStream) {
                        Files.copy(is, outputPath, StandardCopyOption.REPLACE_EXISTING);
                    }
                }
            }
        }
    }
}