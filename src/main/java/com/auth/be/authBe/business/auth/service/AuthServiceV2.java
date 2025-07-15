package com.auth.be.authBe.business.auth.service;

import com.auth.be.authBe.auth.dto.*;
import com.auth.be.authBe.business.auth.model.*;
import com.auth.be.authBe.business.auth.utils.EncryptUtils;
import com.auth.be.authBe.business.auth.utils.JsonUtils;
import com.auth.be.authBe.exception.BadRequestException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Slf4j
@Service
public class AuthServiceV2 {

    @Autowired
    private EncryptUtils encryptUtils;

    @Autowired
    private JsonUtils jsonUtils;

    public SignatureRes generateSignatureAccessToken(GenSignatureAccReq input) {
        String stringToSign = input.getClientId() + "|" + input.getTimestamp();
        String signature = encryptUtils.generateSignatureSnap(stringToSign, input.getPrivateKey());
        return new SignatureRes(signature);
    }

    public SignatureRes generateSignatureTransaction(GenSignatureTrxReq input) {
        // Minify the request body and hash with sha256z
        var body = jsonUtils.minifyJson(input.getBody());
        String bodyToSign = encryptUtils.sha256Hex(body).toLowerCase();

        String stringToSign = null;
//        if (ae.getTokenType().equals(AuthConstant.TOKEN_TYPE_BEARER)) {
//            stringToSign = httpMethod + ":" + relativeUrl + ":" + token + ":" + bodyToSign + ":" + timestamp;
//        } else {
        stringToSign = input.getHttpMethod() + ":" + input.getRelativeUrl() + ":" + input.getAuthorization() + ":" + bodyToSign + ":" + input.getTimestamp();
//        }
//        log.debug("String to sign: [{}]", stringToSign);

        // Generate the signature
        // HMAC SHA512 and encode to base64
        String signature = encryptUtils.hmacSha512(input.getClientSecret(), stringToSign);
        return new SignatureRes(signature);
    }

    public String verifyAccSignature(VerifSignatureAccReq input) {
        byte[] signatureDecode = Base64.getDecoder().decode(input.getSignature());
        String stringToVerify = input.getClientId() + "|" + input.getTimestamp();
        boolean isValid = encryptUtils.validateSignatureSnapAccessToken(signatureDecode, stringToVerify,
                input.getPublicKey());
        if (!isValid) {
            throw new BadRequestException("Signature is not valid");
        }
        return "Signature is valid";
    }

    public String verifyTrxSignature(VerifSignatureTrxReq input) {
        try {
            // Verifikasi X-SIGNATURE
            input.setBody(jsonUtils.minifyJson(input.getBody()));
            // Minify the request body and hash with sha256
            String bodyToSign = encryptUtils.sha256Hex(input.getBody()).toLowerCase();
            String stringToSign = input.getHttpMethod() + ":" + input.getRelativeUrl() + ":" + input.getAuthorization() + ":" + bodyToSign + ":"
                    + input.getTimestamp();
            log.debug("String to sign: [{}]", stringToSign);
            String generatedSignature = encryptUtils.hmacSha512(input.getClientSecret(), stringToSign);
            if (!StringUtils.equals(input.getSignature(), generatedSignature)) {
                throw new BadRequestException("Signature is not valid");
            }
            return "Signature is valid";
        } catch (Exception e) {
            log.debug("Error verifying signature: [{}]", e.getMessage());
            throw new RuntimeException("Error verifying signature", e);
        }
    }
}
