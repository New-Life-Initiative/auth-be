package com.auth.be.authBe.auth;

import org.springframework.stereotype.Component;

import io.micrometer.common.util.StringUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

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
        digest.update(str.getBytes());
        return digest.digest();
    }

    public String sha256Base64(String str) {
        try {
            byte[] hash = sha256(str);
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // public PublicKey getPublicKey(byte[] publicKeyDecode) {
       
    // }
}
