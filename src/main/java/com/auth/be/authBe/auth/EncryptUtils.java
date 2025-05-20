package com.auth.be.authBe.auth;

import org.springframework.stereotype.Component;

import io.micrometer.common.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

@Component
public class EncryptUtils {
    public String encodeBase64(String str) {
        if (StringUtils.isBlank(str)) {
            return "";
        }
        return Base64.getEncoder().encodeToString(str.getBytes());
    }

    public String encodeBase64(byte[] str) {
        return Base64.getEncoder().encodeToString(str);
    }

    public String decodeBase64Str(String str) {
        return Base64.getDecoder().decode(str.getBytes()).toString();
    }

    public byte[] decodeBase64(String str) {
        return Base64.getDecoder().decode(str.getBytes());
    }

    public byte[] sha256(String str) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(str.getBytes(StandardCharsets.UTF_8));
        return digest.digest();
    }

    public String sha256Hex(String str) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(str.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();
        for (byte b : digest.digest()) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public String sha256Base64(String str) {
        try {
            byte hash[] = sha256(str);
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String hmacSha512(String secretKey, String message) {
        try {
            Mac sha512_HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA512");
            sha512_HMAC.init(keySpec);
            byte[] macData = sha512_HMAC.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(macData);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate HMAC SHA512", e);
        }
    }
}
