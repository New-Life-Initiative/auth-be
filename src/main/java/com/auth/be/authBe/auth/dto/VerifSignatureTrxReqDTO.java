package com.auth.be.authBe.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class VerifSignatureTrxReqDTO {
    private String httpMethod;
    private String relativeUrl;
    private String authorization;
    private String clientSecret;
    private String timestamp;
    private String signature;
    private String body;
}
