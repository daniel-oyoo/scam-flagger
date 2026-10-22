package com.scamflagger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class PasswordService {
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public String encode(String password) {
        return encoder.encode(password);
    }

    public boolean matches(String password, String storedHash) {
        if (storedHash.startsWith("pbkdf2:")) {
            return matchesWerkzeugHash(password, storedHash);
        }
        return encoder.matches(password, storedHash);
    }

    private boolean matchesWerkzeugHash(String password, String storedHash) {
        try {
            String[] algorithmAndSalt = storedHash.split("\\$", 3);
            String[] algorithm = algorithmAndSalt[0].split(":");
            if (algorithm.length != 3 || algorithmAndSalt.length != 3
                    || !algorithm[1].equals("sha256")) {
                return false;
            }
            int iterations = Integer.parseInt(algorithm[2]);
            byte[] expected = Base64.getDecoder().decode(algorithmAndSalt[2]);
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(),
                    algorithmAndSalt[1].getBytes(StandardCharsets.UTF_8), iterations, expected.length * 8);
            byte[] actual = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
            spec.clearPassword();
            return MessageDigest.isEqual(expected, actual);
        } catch (Exception exception) {
            return false;
        }
    }
}
