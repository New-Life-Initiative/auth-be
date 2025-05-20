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
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.auth.be.authBe.auth.DTO.AccessTokenBasicReqDTO;
import com.auth.be.authBe.auth.DTO.AccessTokenBasicResDTO;
import com.auth.be.authBe.auth.DTO.SignatureResDTO;
import com.auth.be.authBe.auth.DTO.SnapAccessTokenResDTO;
import com.auth.be.authBe.exception.BadRequestException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class AuthService {
    @Autowired
    private EncryptUtils encryptUtils;
    @Autowired
    private AuthRepository authRepository;
    @Autowired
    private JwtUtil jwtUtil;

    final String AUTH_TYPE_SNAP = "SNAP";
    final String AUTH_TYPE_BASIC = "BASIC";

    final String TOKEN_TYPE_BEARER = "BEARER";
    final String TOKEN_TYPE_BEARERWTOKEN = "BEARERWPREFIX";
    final String TOKEN_TYPE_MAC = "MAC";
    final String CLIENT_CREDENTIALS = "client_credentials";
    final String REFRESH_TOKEN = "refresh_token";
    final String INVALID_GRANT_TYPE = "invalid_grant";
    final String ACCESS_TOKEN_BODY_REQUEST = "{\"grant_type\":\"client_credentials\"}";

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
        log.debug("entity: [{}]", entity);
        if (entity.getChannelId() == null || entity.getChannelId().isEmpty() || entity.getAuthType() == null
                || entity.getAuthType().isEmpty()) {
            throw new BadRequestException("Channel name cannot be null or empty");
        }
        if (entity.getAuthType().equals(AUTH_TYPE_SNAP)) {
            if (entity.getTokenType() == null || entity.getTokenType().isEmpty()) {
                throw new BadRequestException("Token type cannot be null or empty");
            }
            if (!entity.getTokenType().equals(TOKEN_TYPE_BEARER)
                    && !entity.getTokenType().equals(TOKEN_TYPE_BEARERWTOKEN)) {
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
            if (entity.getUsername() == null || entity.getUsername().isEmpty() || entity.getPassword() == null || entity.getPassword().isEmpty()) {
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

    public SignatureResDTO generateSignatureAccessToken(String timestampStr, String partnerId) {

        AuthEntity ae = authRepository.findByClientKey(partnerId);
        if (ae == null) {
            throw new BadRequestException("Auth entity not found");
        }

        String signBase64 = null;
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(ae.getPrivateKey().getBytes()));
            PrivateKey pk = kf.generatePrivate(keySpecPKCS8);
            signature.initSign(pk);
            log.debug("partnerId: [{}]", partnerId);
            log.debug("Timestamp: [{}]", timestampStr);
            String stringToSign = ae.getClientKey() + "|" + timestampStr;
            signature.update(stringToSign.getBytes(StandardCharsets.UTF_8));
            byte[] sign = signature.sign();
            signBase64 = Base64.getEncoder().encodeToString(sign);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException("Error generating signature", e);
        }

        return new SignatureResDTO(signBase64);
    }

    public SignatureResDTO generateSignatureTransaction(String httpMethod, String relativeUrl, String authorization,
            String timestamp, String partnerId, String body) {
        // Validate the request
        if (httpMethod == null || httpMethod.isEmpty() || relativeUrl == null || relativeUrl.isEmpty()
                || authorization == null || authorization.isEmpty() || timestamp == null || timestamp.isEmpty()) {
            throw new BadRequestException(
                    "HTTP Method, Relative URL, Authorization, Timestamp, and PartnerId cannot be null or empty");
        }

        String[] authParts = authorization.split(" ");
        if (authParts.length != 2 || !authParts[0].equalsIgnoreCase("Bearer")) {
            throw new BadRequestException("Authorization header must be in the format 'Bearer <token>'");
        }
        String token = authParts[1];

        // Get auth infomation base on channelId and authType
        AuthEntity ae = authRepository.findByClientKey(partnerId);
        if (ae == null) {
            throw new BadRequestException("Auth entity not found");
        }

        String signature = null;
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readValue(body, JsonNode.class);
            body = jsonNode.toString();
            // Minify the request body and hash with sha256z
            String bodyToSign = encryptUtils.sha256Hex(body).toLowerCase();
            log.debug("Body to sign: [{}]", bodyToSign);
            String stringToSign = null;
            if (ae.getTokenType().equals(TOKEN_TYPE_BEARER)) {
                stringToSign = httpMethod + ":" + relativeUrl + ":" + token + ":" + bodyToSign + ":" + timestamp;
            } else {
                stringToSign = httpMethod + ":" + relativeUrl + ":" + authorization + ":" + bodyToSign + ":" + timestamp;
            }
            log.debug("String to sign: [{}]", stringToSign);

            // Generate the signature
            // HMAC SHA512 and encode to base64
            signature = encryptUtils.hmacSha512(ae.getClientSecret(), stringToSign);
        } catch (NoSuchAlgorithmException | JsonProcessingException e) {
            e.printStackTrace();
        }
        return new SignatureResDTO(signature);
    }

    public SnapAccessTokenResDTO verifySnapAccessToken(String partnerId, String timestampStr, String signature,
            String clientKey,
            String body) {
        // Validate the request
        if (partnerId == null || partnerId.isEmpty() || timestampStr == null || timestampStr.isEmpty()
                || signature == null || signature.isEmpty() || clientKey == null || clientKey.isEmpty()) {
            throw new BadRequestException("Partner ID, Timestamp, Signature and Client Key cannot be null or empty");
        }
        log.debug("Body: [{}]", body);
        // log.debug("Body: [{}]", body.equals(ACCESS_TOKEN_BODY_REQUEST));
        // Validate the body
        if (body.isBlank() || body.isEmpty()) {
            throw new BadRequestException("Body cannot be null or empty");
        }
        if (!body.equals(ACCESS_TOKEN_BODY_REQUEST)) {
            throw new BadRequestException("Missing grant_type in body");
        }

        AuthEntity ae = authRepository.findByClientKey(clientKey);
        if (ae == null) {
            throw new BadRequestException("Client key not found");
        }

        try {
            byte[] signatureDecode = Base64.getDecoder().decode(signature);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(ae.getPublicKey()));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(keySpec);

            Signature signatureIns = Signature.getInstance("SHA256withRSA");
            signatureIns.initVerify(publicKey);

            String stringToVerify = clientKey + "|" + timestampStr;
            // log.debug("Timestamp: [{}]", timestampStr);
            // log.debug("String to verify: [{}]", stringToVerify);
            // log.debug("Public key: [{}]", ae.getPublicKey());
            // log.debug("Private key: [{}]", ae.getPrivateKey());
            // log.debug("Incoming signature: [{}]", signature);
            signatureIns.update(stringToVerify.getBytes(StandardCharsets.UTF_8));

            boolean isValid = signatureIns.verify(signatureDecode);
            // log.debug("Signature verification result: {}", isValid);

            if (!isValid) {
                throw new BadRequestException("Signature is not valid");
            }

        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new RuntimeException("Error verifying signature", e);
        }

        return new SnapAccessTokenResDTO(
                jwtUtil.generateToken(clientKey, ae.getAccessTokenExpiryTime()),
                ae.getTokenType(), ae.getAccessTokenExpiryTime());
    }

    public String verifySnapTransaction(String httpMethod, String partnerId, String relativeUrl, String authorization,
            String timestamp, String channelId, String signature, String body) {
        // Authorization
        // X-TIMESTAMP
        // X-SIGNATURE
        // X-PARTNER-ID -> client key
        // X-EXTERNAL-ID -> Numeric String. Reference number that should be unique in
        // the same day
        // CHANNEL-ID
        // BODY

        // Tahapan verifikasi
        // 1. Verifikasi Authorization ✅
        // 2. Verifikasi client key yang di dapat dari jwt sama dengan client key yang
        // di dapat dari X-PARTNER-ID ✅
        // 3. Verifikasi X-PARTNER-ID di Database ✅
        // 5. Verrifikasi X-EXTERNAL-ID ❌
        // 4. Verifikasi X-SIGNATURE

        // Verifikasi Header
        log.debug(
                "Verifying transaction with httpMethod: [{}], partnerId: [{}], relativeUrl: [{}], authorization: [{}], timestamp: [{}], channelId: [{}], signature: [{}], body: [{}]",
                httpMethod, partnerId, relativeUrl, authorization, timestamp, channelId, signature, body);
        log.debug("Is httpmethod POST: [{}]", httpMethod.equals("POST"));
        if (httpMethod == null || httpMethod.isEmpty() || relativeUrl == null || relativeUrl.isEmpty()) {
            throw new BadRequestException("HTTP Method and Relative URL cannot be null or empty");
        }
        if (!httpMethod.equals("POST") && !httpMethod.equals("PUT") && !httpMethod.equals("DELETE")
                && !httpMethod.equals("PATCH") && !httpMethod.equals("GET")) {
            throw new BadRequestException("Http Method must be POST, PUT, DELETE, PATCH or GET");
        }
        if (authorization == null || authorization.isEmpty() || timestamp == null || timestamp.isEmpty()) {
            throw new BadRequestException("Authorization and Timestamp cannot be null or empty");
        }
        if (channelId == null || channelId.isEmpty() || signature == null || signature.isEmpty()) {
            throw new BadRequestException("Channel ID and Auth Type cannot be null or empty");
        }
        // Verifikasi Body
        if (body == null || body.isEmpty()) {
            throw new BadRequestException("Body cannot be null or empty");
        }

        // Verifikasi X-PARTNER-ID di Database
        AuthEntity ae = authRepository.findByClientKey(partnerId);
        if (ae == null) {
            throw new BadRequestException("Partner not found");
        }

        // Verifikasi Authorization / Access Token
        String[] authParts = authorization.split(" ");
        if (authParts.length != 2 || !authParts[0].equalsIgnoreCase("Bearer")) {
            throw new BadRequestException("Authorization header must be in the format 'Bearer <token>'");
        }
        String token = authParts[1];
        Boolean isValidToken = jwtUtil.validateToken(token, partnerId);
        if (!isValidToken) {
            throw new BadRequestException("Access token is not valid");
        }
        Boolean isTokenExpired = jwtUtil.extractExpiration(token).before(new Date());
        if (isTokenExpired) {
            throw new BadRequestException("Access token is expired");
        }
        // Verifikasi client key yang di dapat dari jwt sama dengan client key yang di
        // dapat dari X-PARTNER-ID
        String username = jwtUtil.extractUsername(token);
        if (!username.equals(partnerId)) {
            throw new BadRequestException("Access token is not valid");
        }
        // TODO: Handle X-EXTERNAL-ID
        try {
            // Verifikasi X-SIGNATURE

            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readValue(body, JsonNode.class);
            body = jsonNode.toString();
            // Minify the request body and hash with sha256
            String bodyToSign = encryptUtils.sha256Hex(body).toLowerCase();
            String stringToSign = null;
            if (ae.getTokenType().equals(TOKEN_TYPE_BEARER)) {
                stringToSign = httpMethod + ":" + relativeUrl + ":" +  token + ":" + bodyToSign + ":" + timestamp;
            } else {
                stringToSign = httpMethod + ":" + relativeUrl + ":" + authorization + ":" + bodyToSign + ":" + timestamp;
            }
            log.debug("String to sign: [{}]", stringToSign);
            String generatedSignature = encryptUtils.hmacSha512(ae.getClientSecret(), stringToSign);
            if (StringUtils.equals(signature, generatedSignature)) {
                throw new BadRequestException("Signature is not valid");
            }
        } catch (Exception e) {
            log.debug("Error verifying signature: [{}]", e.getMessage());
            throw new RuntimeException("Error verifying signature", e);
        }
        return "SUCCESS";
    }

    public AccessTokenBasicResDTO verifyBasicAccessToken(String username, String password, AccessTokenBasicReqDTO body) {
        log.debug("Username: [{}]", username);
        log.debug("Password: [{}]", password);
        log.debug("Body: [{}]", body);
        // Validate the request
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            throw new BadRequestException("Username and Password cannot be null or empty");
        }
        if (body == null) {
            throw new BadRequestException("Body cannot be null");
        }
        if (body.getGrant_type() == null || body.getGrant_type().isEmpty()) {
            throw new BadRequestException("Grant type cannot be null or empty");
        }
        
        AuthEntity ae = authRepository.findByUsernameAndPassword(username, password);
        if (body.getGrant_type().equals(REFRESH_TOKEN) || body.getGrant_type().equals(CLIENT_CREDENTIALS)) {
            if (body.getGrant_type().equals(REFRESH_TOKEN)) {
                // Check if refresh token is valid
                if (body.getRefresh_token() == null || body.getRefresh_token().isEmpty()) {
                    throw new BadRequestException("Refresh token cannot be null or empty");
                }
                
                Boolean isValidToken = jwtUtil.validateTokenBasic(body.getRefresh_token(), ae.getClientKey(), "REFRESH");
                if (!isValidToken) {
                    throw new BadRequestException("Refresh token is not valid");
                }
            }
        } else if (body.getGrant_type().equals(INVALID_GRANT_TYPE)) {
            throw new BadRequestException("Invalid grant type");
        } else {
            throw new BadRequestException("Grant type must be client_credentials or refresh_token");
        }

        // Generate the access token
        String accessToken = jwtUtil.generateTokenBasic(ae.getClientKey(), ae.getAccessTokenExpiryTime(), "ACCESS");
        // Generate the refresh token
        String refreshToken = jwtUtil.generateTokenBasic(ae.getClientKey(), ae.getAccessTokenExpiryTime(), "REFRESH");

        return new AccessTokenBasicResDTO(
                accessToken,
                refreshToken
            );
    }

    public AccessTokenBasicResDTO verifyBasicTransaction(String username, String password, AccessTokenBasicReqDTO body) {
        log.debug("Username: [{}]", username);
        log.debug("Password: [{}]", password);
        log.debug("Body: [{}]", body);
        // Validate the request
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            throw new BadRequestException("Username and Password cannot be null or empty");
        }
        if (body == null) {
            throw new BadRequestException("Body cannot be null");
        }
        if (body.getGrant_type() == null || body.getGrant_type().isEmpty()) {
            throw new BadRequestException("Grant type cannot be null or empty");
        }
        
        AuthEntity ae = authRepository.findByUsernameAndPassword(username, password);
        if (body.getGrant_type().equals(REFRESH_TOKEN) || body.getGrant_type().equals(CLIENT_CREDENTIALS)) {
            if (body.getGrant_type().equals(REFRESH_TOKEN)) {
                // Check if refresh token is valid
                if (body.getRefresh_token() == null || body.getRefresh_token().isEmpty()) {
                    throw new BadRequestException("Refresh token cannot be null or empty");
                }
                
                Boolean isValidToken = jwtUtil.validateTokenBasic(body.getRefresh_token(), ae.getClientKey(), "REFRESH");
                if (!isValidToken) {
                    throw new BadRequestException("Refresh token is not valid");
                }
            }
        } else if (body.getGrant_type().equals(INVALID_GRANT_TYPE)) {
            throw new BadRequestException("Invalid grant type");
        } else {
            throw new BadRequestException("Grant type must be client_credentials or refresh_token");
        }

        // Generate the access token
        String accessToken = jwtUtil.generateTokenBasic(ae.getClientKey(), ae.getAccessTokenExpiryTime(), "ACCESS");
        // Generate the refresh token
        String refreshToken = jwtUtil.generateTokenBasic(ae.getClientKey(), ae.getAccessTokenExpiryTime(), "REFRESH");

        return new AccessTokenBasicResDTO(
                accessToken,
                refreshToken
            );
    }
};