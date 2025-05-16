package com.auth.be.authBe.auth;

import java.time.ZonedDateTime;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
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

    @PostMapping("/generate/signature")
    public String generateSignature(@RequestHeader("X-TIMESTAMP") String timestamp, @RequestBody GenSignatureReqDTO entity) {
        return authService.generateSignature(timestamp, entity);
    }

    @PostMapping("/verify/snap/access-token")
    public String verifySnapAccessToken(
            @RequestHeader("X-PARTNER_ID") String partnerId,
            @RequestHeader("X-TIMESTAMP") String timestamp,
            @RequestHeader("X-SIGNATURE") String signature,
            @RequestHeader("X-CLIENT-KEY") String clientKey,
            @RequestBody Map<String, String> body
    ) {
        return authService.verifySnapAccessToken(partnerId, timestamp, signature, clientKey, body);
    }

}
