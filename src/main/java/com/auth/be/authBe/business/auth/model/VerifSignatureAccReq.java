package com.auth.be.authBe.business.auth.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class VerifSignatureAccReq {
    private String clientId;
    private String timestamp;
    private String publicKey;
    private String signature;
}
