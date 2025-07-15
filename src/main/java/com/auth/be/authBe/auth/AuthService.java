package com.auth.be.authBe.auth;

import java.security.KeyPair;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.UUID;

import com.auth.be.authBe.auth.dto.*;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.auth.be.authBe.auth.constant.AuthConstant;
import com.auth.be.authBe.business.auth.utils.EncryptUtils;
import com.auth.be.authBe.business.auth.utils.JsonUtils;
import com.auth.be.authBe.business.auth.utils.JwtUtil;
import com.auth.be.authBe.exception.BadRequestException;

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
    @Autowired
    private JsonUtils jsonUtils;

    public AuthEntity generateSnapClient(AuthEntity request) {
        // Generate client key and secret key
        if (request.getChannelId() == null || request.getChannelId().isEmpty()) {
            throw new BadRequestException("Channel name cannot be null or empty");
        }
        request.setClientKey(encryptUtils.encodeBase64(UUID.randomUUID().toString()).substring(0, 36));
        request.setClientSecret(encryptUtils
                .sha256Base64(
                        request.getChannelId() + "|" + AuthConstant.AUTH_TYPE_SNAP + "|" + request.getClientKey()));
        return request;
    }

    public AuthEntity generateSnapRsa(AuthEntity request) {
        KeyPair keyPair = encryptUtils.generateRSA();
        request.setPublicKey(encryptUtils.encodeBase64(keyPair.getPublic().getEncoded()));
        request.setPrivateKey(encryptUtils.encodeBase64(keyPair.getPrivate().getEncoded()));
        return request;
    }

    public AuthEntity generateBasic(AuthEntity request) {
        request.setUsername(UUID.randomUUID().toString().substring(0, 8));
        request.setPassword(UUID.randomUUID().toString().substring(0, 32));
        return request;
    }

    public AuthEntity generateSave(AuthEntity request) {
        // Validation
        log.debug("request: [{}]", request);
        request.validateSave();
        // Check if the auth entity already exists
        AuthEntity ae = authRepository.findByChannelIdAndAuthType(request.getChannelId(), request.getAuthType());
        LocalDateTime now = LocalDateTime.now();
        if (ae != null) {
            // If it exists, update the existing entity
            ae.setTokenType(request.getTokenType());
            ae.setClientKey(request.getClientKey());
            ae.setClientSecret(request.getClientSecret());
            ae.setPublicKey(request.getPublicKey());
            ae.setPrivateKey(request.getPrivateKey());
            ae.setAccessTokenExpiryTime(request.getAccessTokenExpiryTime());
            ae.setRefreshTokenExpiryTime(request.getRefreshTokenExpiryTime());
            ae.setStatus(request.getStatus());
            ae.setUpdatedAt(now);
            return authRepository.save(ae);
        } else {
            // If it doesn't exist, save the new entity
            request.setUpdatedAt(now);
            request.setCreatedAt(now);
            return authRepository.save(request);
        }
    }

    public SignatureResDTO generateSignatureAccessToken(String timestampStr, String clientKey) {
        AuthEntity ae = authRepository.findByClientKey(clientKey);
        if (ae == null) {
            throw new BadRequestException("Auth entity not found");
        }
        String stringToSign = clientKey + "|" + timestampStr;
        log.debug("Timestamp: [{}]", timestampStr);
        String signature = encryptUtils.generateSignatureSnap(stringToSign, ae.getPrivateKey());
        return new SignatureResDTO(signature);
    }

    public SignatureResDTO generateSignatureTransaction(String httpMethod, String relativeUrl, String authorization,
            String timestamp, String partnerId, String body) {
        // Validate the request
        if (httpMethod == null || httpMethod.isEmpty() || relativeUrl == null || relativeUrl.isEmpty()
                || authorization == null || authorization.isEmpty() || timestamp == null || timestamp.isEmpty()) {
            throw new BadRequestException(
                    "HTTP Method, Relative URL, Authorization, Timestamp, and PartnerId is required");
        }
        if (body == null || body.isEmpty()) {
            throw new BadRequestException("Body is required");
        }

        // Validate authorization have bearer
        String[] authParts = authorization.split(" ");
        if (authParts.length != 2 || !authParts[0].equalsIgnoreCase("Bearer")) {
            throw new BadRequestException("Authorization header must be in the format 'Bearer <token>'");
        }
        String token = authParts[1];

        // Get auth infomation base on client key
        AuthEntity ae = authRepository.findByClientKey(partnerId);
        if (ae == null) {
            throw new BadRequestException("Auth entity not found");
        }

        // Minify the request body and hash with sha256z
        body = jsonUtils.minifyJson(body);
        String bodyToSign = encryptUtils.sha256Hex(body).toLowerCase();
        log.debug("Body to sign: [{}]", bodyToSign);

        String stringToSign = null;
        if (ae.getTokenType().equals(AuthConstant.TOKEN_TYPE_BEARER)) {
            stringToSign = httpMethod + ":" + relativeUrl + ":" + token + ":" + bodyToSign + ":" + timestamp;
        } else {
            stringToSign = httpMethod + ":" + relativeUrl + ":" + authorization + ":" + bodyToSign + ":" + timestamp;
        }
        log.debug("String to sign: [{}]", stringToSign);

        // Generate the signature
        // HMAC SHA512 and encode to base64
        String signature = encryptUtils.hmacSha512(ae.getClientSecret(), stringToSign);
        return new SignatureResDTO(signature);
    }

    public SnapAccessTokenResDTO verifySnapAccessToken(String partnerId, String timestampStr, String signature,
            String clientKey, String body) {
        // Validate the request
        if (partnerId == null || partnerId.isEmpty() || timestampStr == null || timestampStr.isEmpty()
                || signature == null || signature.isEmpty() || clientKey == null || clientKey.isEmpty()) {
            throw new BadRequestException("Partner ID, Timestamp, Signature and Client Key cannot be null or empty");
        }
        if (body.isBlank()) {
            throw new BadRequestException("Body cannot be null or empty");
        }
        if (!body.equals(AuthConstant.ACCESS_TOKEN_BODY_REQUEST)) {
            throw new BadRequestException("Missing grant_type in body");
        }
        log.debug("Body: [{}]", body);
        AuthEntity ae = authRepository.findByClientKey(clientKey);
        if (ae == null) {
            throw new BadRequestException("Client key not found");
        }
        byte[] signatureDecode = Base64.getDecoder().decode(signature);
        String stringToVerify = clientKey + "|" + timestampStr;
        log.debug("String to verify: [{}]", stringToVerify);
        boolean isValid = encryptUtils.validateSignatureSnapAccessToken(signatureDecode, stringToVerify,
                ae.getPublicKey());
        if (!isValid) {
            throw new BadRequestException("Signature is not valid");
        }
        return new SnapAccessTokenResDTO(
                jwtUtil.generateToken(clientKey, ae.getAccessTokenExpiryTime()),
                ae.getTokenType(), ae.getAccessTokenExpiryTime());
    }

    public String verifySnapTransaction(String httpMethod, String partnerId, String relativeUrl, String authorization,
            String timestamp, String channelId, String signature, String body) {
        // Tahapan verifikasi
        // 1. Verifikasi Authorization ✅
        // 2. Verifikasi client key yang di dapat dari jwt sama dengan client key yang
        // di dapat dari X-PARTNER-ID ✅
        // 3. Verifikasi X-PARTNER-ID di Database ✅
        // 5. Verrifikasi X-EXTERNAL-ID ❌
        // 4. Verifikasi X-SIGNATURE ✅

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
        // TODO: Handle X-EXTERNAL-ID
        try {
            // Verifikasi X-SIGNATURE
            body = jsonUtils.minifyJson(body);
            // Minify the request body and hash with sha256
            String bodyToSign = encryptUtils.sha256Hex(body).toLowerCase();
            String stringToSign = null;
            if (ae.getTokenType().equals(AuthConstant.TOKEN_TYPE_BEARER)) {
                stringToSign = httpMethod + ":" + relativeUrl + ":" + token + ":" + bodyToSign + ":" + timestamp;
            } else {
                stringToSign = httpMethod + ":" + relativeUrl + ":" + authorization + ":" + bodyToSign + ":"
                        + timestamp;
            }
            log.debug("String to sign: [{}]", stringToSign);
            String generatedSignature = encryptUtils.hmacSha512(ae.getClientSecret(), stringToSign);
            if (!StringUtils.equals(signature, generatedSignature)) {
                throw new BadRequestException("Signature is not valid");
            }
        } catch (Exception e) {
            log.debug("Error verifying signature: [{}]", e.getMessage());
            throw new RuntimeException("Error verifying signature", e);
        }
        return "SUCCESS";
    }

    public AccessTokenBasicResDTO verifyBasicAccessToken(String username, String password,
            AccessTokenBasicReqDTO body) {
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
        body.validate();

        AuthEntity ae = authRepository.findByUsernameAndPassword(username, password);
        if (body.getGrant_type().equals(AuthConstant.REFRESH_TOKEN)) {
            Boolean isValidToken = jwtUtil.validateTokenBasic(body.getRefresh_token(), ae.getClientKey(),
                    "REFRESH");
            if (!isValidToken) {
                throw new BadRequestException("Refresh token is not valid");
            }
        }
        String accessToken = jwtUtil.generateTokenBasic(ae.getUsername(), ae.getAccessTokenExpiryTime(), "ACCESS");
        String refreshToken = jwtUtil.generateTokenBasic(ae.getUsername(), ae.getAccessTokenExpiryTime(), "REFRESH");

        return new AccessTokenBasicResDTO(accessToken, refreshToken);
    }

    public String verifyBasicTransaction(String authorization) {
        if (authorization == null || authorization.isEmpty()) {
            throw new BadRequestException("Authorization cannot be null or empty");
        }
        String[] authParts = authorization.split(" ");
        if (authParts.length != 2 || !authParts[0].equalsIgnoreCase("Bearer")) {
            throw new BadRequestException("Authorization header must be in the format 'Bearer <token>'");
        }
        log.debug("authorization: [{}]", authorization);
        String token = authParts[1];
        // Validate the token
        Boolean isValidToken = jwtUtil.validateTokenBasic(token, "ACCESS");
        if (!isValidToken) {
            throw new BadRequestException("Access token is not valid");
        }
        final String extractedUsername = jwtUtil.extractUsername(token);
        boolean isUsernameExists = authRepository.existsByUsername(extractedUsername);
        if (!isUsernameExists) {
            throw new BadRequestException("Access token is not valid");
        }
        return "SUCCESS";
    }

}