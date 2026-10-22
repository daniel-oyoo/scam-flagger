package com.scamflagger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.junit.jupiter.api.Test;

class PasswordServiceTest {
    private final PasswordService passwordService = new PasswordService();

    @Test
    void verifiesWerkzeugPbkdf2HashesForExistingAccounts() throws Exception {
        String password = "legacy-password";
        String salt = "legacy-salt";
        int iterations = 1000;
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(),
                salt.getBytes(StandardCharsets.UTF_8), iterations, 256);
        byte[] digest = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).getEncoded();
        String hash = "pbkdf2:sha256:" + iterations + "$" + salt + "$"
                + Base64.getEncoder().encodeToString(digest);

        assertTrue(passwordService.matches(password, hash));
        assertFalse(passwordService.matches("wrong-password", hash));
    }
}
