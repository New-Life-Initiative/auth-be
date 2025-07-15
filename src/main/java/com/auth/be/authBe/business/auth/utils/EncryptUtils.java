package com.auth.be.authBe.business.auth.utils;

import org.springframework.stereotype.Component;

import io.micrometer.common.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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

    public String sha256Hex(String str){
        try {
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
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate SHA-256 hash", e);
        }
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

    public KeyPair generateRSA() {
        KeyPair keyPair = null;
        try {
            SecureRandom secureRandom = new SecureRandom();
            KeyPairGenerator keyPairGenerator;
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(512, secureRandom);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return keyPair;
    }

    public String generateSignatureSnap(String stringToSign, String privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(
                    Base64.getDecoder().decode(privateKey.getBytes()));
            PrivateKey pk = kf.generatePrivate(keySpecPKCS8);
            signature.initSign(pk);
            signature.update(stringToSign.getBytes(StandardCharsets.UTF_8));
            byte[] sign = signature.sign();
            return Base64.getEncoder().encodeToString(sign);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException("Error generating signature", e);
        }
    }

    public boolean validateSignatureSnapAccessToken(byte[] signatureDecode, String stringToVerify, String publicKeyStr) {
            boolean result = false;
            try {
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyStr));
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey publicKey = kf.generatePublic(keySpec);
                Signature signatureIns = Signature.getInstance("SHA256withRSA");
                signatureIns.initVerify(publicKey);
                signatureIns.update(stringToVerify.getBytes(StandardCharsets.UTF_8));
                result = signatureIns.verify(signatureDecode);
            } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
                e.printStackTrace();
            }
            return result;
    }
}
