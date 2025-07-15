package com.auth.be.authBe.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class VerifSignatureAccReqDTO {
    private String clientId;
    private String timestamp;
    private String publicKey;
    private String signature;
}
