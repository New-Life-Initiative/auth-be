package com.auth.be.authBe.auth;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestHeader;

import com.auth.be.authBe.exception.BadRequestException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class AuthService {
    @Autowired
    private EncryptUtils encryptUtils;
    @Autowired
    private AuthRepository authRepository;

    final String AUTH_TYPE_SNAP = "SNAP";
    final String AUTH_TYPE_BASIC = "BASIC";

    final String TOKEN_TYPE_BEARER = "BEARER";
    final String TOKEN_TYPE_BEARERWTOKEN = "BEARERWPREFIX";
    final String TOKEN_TYPE_MAC = "MAC";

    public AuthEntity generateSnapClient(AuthEntity entity) {
        // Generate client key and secret key
        entity.setClientKey(encryptUtils.encodeBase64(UUID.randomUUID().toString()).substring(0, 36));
        entity.setClientSecret(encryptUtils
                .sha256Base64(entity.getChannelId() + "|" + AUTH_TYPE_SNAP + "|" + entity.getClientKey()));
        return entity;
    }

    public AuthEntity generateSnapRsa(AuthEntity entity) {
        // Generate public key and private key
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(512, secureRandom);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            entity.setPublicKey(encryptUtils.encodeBase64(publicKey.getEncoded()));
            entity.setPrivateKey(encryptUtils.encodeBase64(privateKey.getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return entity;
    }

    public AuthEntity generateBasic(AuthEntity entity) {
        // Generate username and password
        entity.setUsername(UUID.randomUUID().toString().substring(0, 8));
        entity.setPassword(UUID.randomUUID().toString().substring(0, 32));
        return entity;
    }

    public AuthEntity generateSave(AuthEntity entity) {
        // Validation
        log.debug("Validating entity: [{}]", entity);
        if (entity.getChannelId() == null || entity.getChannelId().isEmpty() || entity.getAuthType() == null
                || entity.getAuthType().isEmpty()) {
            throw new BadRequestException("Channel name cannot be null or empty");
        }
        if (entity.getAuthType().equals(AUTH_TYPE_SNAP)) {
            if (entity.getTokenType() == null || entity.getTokenType().isEmpty()) {
                throw new BadRequestException("Token type cannot be null or empty");
            }
            if (!entity.getTokenType().equals(TOKEN_TYPE_BEARER)
                    && !entity.getTokenType().equals(TOKEN_TYPE_BEARERWTOKEN)
                    && !entity.getTokenType().equals(TOKEN_TYPE_MAC)) {
                throw new BadRequestException("Token type must be BEARER, BEARERWPREFIX or MAC");
            }
            if (entity.getClientKey() == null || entity.getClientKey().isEmpty() || entity.getClientSecret() == null
                    || entity.getClientSecret().isEmpty()) {
                throw new BadRequestException("Client key and Client secret cannot be null or empty");
            }
            if (entity.getPublicKey() == null || entity.getPublicKey().isEmpty() || entity.getPrivateKey() == null
                    || entity.getPrivateKey().isEmpty()) {
                throw new BadRequestException("Public key and Private key cannot be null or empty");
            }
            if (entity.getAccessTokenExpiryTime() == null || entity.getStatus() == null
                    || entity.getStatus().isEmpty()) {
                throw new BadRequestException("Access token expiry and Status cannot be null or empty");
            }
            // if (entity.getStatus() != "1" || entity.getStatus() != "0") {
            // throw new BadRequestException("Status must be 1 or 0");
            // }
        }
        if (entity.getAuthType().equals(AUTH_TYPE_BASIC)) {
            if (entity.getClientKey() == null || entity.getUsername().isEmpty() || entity.getPassword() == null
                    || entity.getClientSecret().isEmpty()) {
                throw new BadRequestException("Username and Password cannot be null or empty");
            }
            if (entity.getAccessTokenExpiryTime() == null || entity.getRefreshTokenExpiryTime() == null) {
                throw new BadRequestException("Access token expiry and Refresh token expiry cannot be null or empty");
            }
            if (entity.getStatus() == null || entity.getStatus().isEmpty()) {
                throw new BadRequestException("Status cannot be null or empty");
            }
            // if (entity.getStatus() != "1" || entity.getStatus() != "0") {
            // throw new BadRequestException("Status must be 1 or 0");
            // }
        }
        // Check if the auth entity already exists
        AuthEntity ae = authRepository.findByChannelIdAndAuthType(entity.getChannelId(), entity.getAuthType());
        LocalDateTime now = LocalDateTime.now();
        if (ae != null) {
            // If it exists, update the existing entity
            ae.setTokenType(entity.getTokenType());
            ae.setClientKey(entity.getClientKey());
            ae.setClientSecret(entity.getClientSecret());
            ae.setPublicKey(entity.getPublicKey());
            ae.setPrivateKey(entity.getPrivateKey());
            ae.setAccessTokenExpiryTime(entity.getAccessTokenExpiryTime());
            ae.setRefreshTokenExpiryTime(entity.getRefreshTokenExpiryTime());
            ae.setStatus(entity.getStatus());
            ae.setUpdatedAt(now);
            return authRepository.save(ae);
        } else {
            // If it doesn't exist, save the new entity
            entity.setUpdatedAt(now);
            entity.setCreatedAt(now);
            return authRepository.save(entity);
        }
    }

    public String generateSignature(String timestampStr, GenSignatureReqDTO input) {
        if (input.getChannelId() == null || input.getChannelId().isEmpty() || input.getAuthType() == null
                || input.getAuthType().isEmpty()) {
            throw new BadRequestException("Channel name cannot be null or empty");
        }

        AuthEntity ae = authRepository.findByChannelIdAndAuthType(input.getChannelId(), input.getAuthType());
        if (ae == null) {
            throw new BadRequestException("Auth entity not found");
        }

        String signBase64 = null;
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(
                    Base64.getDecoder().decode(ae.getPrivateKey().getBytes()));
            PrivateKey pk = kf.generatePrivate(keySpecPKCS8);
            signature.initSign(pk);

            log.debug("Timestamp: [{}]", timestampStr);
            String stringToSign = ae.getClientKey() + "|" + timestampStr;
            log.debug("String to sign: [{}]", stringToSign);
            signature.update(stringToSign.getBytes(StandardCharsets.UTF_8));
            byte[] sign = signature.sign();
            signBase64 = Base64.getEncoder().encodeToString(sign);
            log.debug("Generated signature: [{}]", signBase64);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException("Error generating signature", e);
        }

        return signBase64;
    }

    public String verifySnapAccessToken(String partnerId, String timestampStr, String signature, String clientKey,
            Map<String, String> body) {
        // Validate the request
        if (partnerId == null || partnerId.isEmpty() || timestampStr == null || timestampStr.isEmpty()
                || signature == null || signature.isEmpty() || clientKey == null || clientKey.isEmpty()) {
            throw new BadRequestException("Partner ID, Timestamp, Signature and Client Key cannot be null or empty");
        }
        // Validate the body
        if (body == null || body.isEmpty()) {
            throw new BadRequestException("Body cannot be null or empty");
        }

        AuthEntity ae = authRepository.findByClientKey(clientKey);
        if (ae == null) {
            throw new BadRequestException("Client key not found");
        }

        try {
            byte[] publicKeyDecode = Base64.getDecoder().decode(ae.getPublicKey());
            byte[] signatureDecode = Base64.getDecoder().decode(signature);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyDecode);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(keySpec);

            Signature signatureIns = Signature.getInstance("SHA256withRSA");
            signatureIns.initVerify(publicKey);

            log.debug("Timestamp: [{}]", timestampStr);
            String stringToVerify = clientKey + "|" + timestampStr;
            log.debug("String to verify: [{}]", stringToVerify);
            log.debug("Incoming signature: [{}]", signature);
            signatureIns.update(stringToVerify.getBytes(StandardCharsets.UTF_8));

            boolean isValid = signatureIns.verify(signatureDecode);
            log.debug("Signature verification result: {}", isValid);

            if (!isValid) {
                throw new BadRequestException("Signature is not valid");
            }

            return "Signature verified successfully";
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new RuntimeException("Error verifying signature", e);
        }
    }
}
