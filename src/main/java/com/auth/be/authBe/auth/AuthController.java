package com.auth.be.authBe.auth;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.be.authBe.auth.DTO.AccessTokenBasicReqDTO;
import com.auth.be.authBe.auth.DTO.AccessTokenBasicResDTO;
import com.auth.be.authBe.auth.DTO.SignatureResDTO;
import com.auth.be.authBe.auth.DTO.SnapAccessTokenResDTO;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin(origins = "*")
public class AuthController {
    // Generate Client Key and Secret Key
    @Autowired
    private AuthService authService;

    @PostMapping("/generate/snap-client")
    public AuthEntity generateSnapClient(@RequestBody AuthEntity entity) {
        return authService.generateSnapClient(entity);
    }

    @PostMapping("/generate/snap-rsa")
    public AuthEntity generateSnapRsa(@RequestBody AuthEntity entity) {
        return authService.generateSnapRsa(entity);
    }

    @PostMapping("/generate/basic")
    public AuthEntity generateBasic(@RequestBody AuthEntity entity) {
        return authService.generateBasic(entity);
    }

    @PostMapping("/generate/save")
    public AuthEntity generateSave(@RequestBody AuthEntity entity) {
        return authService.generateSave(entity);
    }

    @PostMapping("/generate/signature/access-token")
    public SignatureResDTO generateSignatureAccessToken(@RequestHeader("X-TIMESTAMP") String timestamp, @RequestHeader("X-PARTNER-ID") String partnerId) {
        return authService.generateSignatureAccessToken(timestamp, partnerId);
    }

    @PostMapping("/generate/signature/transaction")
    public SignatureResDTO generateSignatureTransaction(
        @RequestHeader("HTTP-METHOD") String httpMethod, //
        @RequestHeader("RELATIVE-URL") String relativeUrl, //
        @RequestHeader("Authorization") String authorization, //
        @RequestHeader("X-TIMESTAMP") String timestamp, //
        @RequestHeader("X-PARTNER-ID") String partnerId, //
        @RequestBody String body //
    ) {
        return authService.generateSignatureTransaction(httpMethod, relativeUrl, authorization, timestamp, partnerId, body);
    }
    
    @PostMapping("/verify/snap/access-token")
    public SnapAccessTokenResDTO verifySnapAccessToken(
            @RequestHeader("X-PARTNER-ID") String partnerId,
            @RequestHeader("X-TIMESTAMP") String timestamp,
            @RequestHeader("X-SIGNATURE") String signature,
            @RequestHeader("X-CLIENT-KEY") String clientKey,
            @RequestBody String body
    ) {
        return authService.verifySnapAccessToken(partnerId, timestamp, signature, clientKey, body);
    }

    @PostMapping("/verify/snap/transaction")
    public String verifySnapTransaction(
        @RequestHeader("HTTP-METHOD") String httpMethod, //
        @RequestHeader("X-PARTNER-ID") String partnerId, //
        @RequestHeader("RELATIVE-URL") String relativeUrl, //
        @RequestHeader("Authorization") String authorization, //
        @RequestHeader("X-TIMESTAMP") String timestamp, //
        @RequestHeader("CHANNEL-ID") String channelId,  //
        @RequestHeader("X-SIGNATURE") String signature, //
        @RequestBody String body //
    ) {
        return authService.verifySnapTransaction(httpMethod, partnerId, relativeUrl, authorization, timestamp, channelId, signature, body);
    }

    @PostMapping("/verify/basic/access-token")
    public AccessTokenBasicResDTO verifyBasicAccessToken(
        @RequestHeader("Username") String username, //
        @RequestHeader("Password") String password, //
        @RequestBody AccessTokenBasicReqDTO body //
        // Body -> grant_type, refresh_token 
    ) {
        return authService.verifyBasicAccessToken(username, password, body);
    }
    
}
