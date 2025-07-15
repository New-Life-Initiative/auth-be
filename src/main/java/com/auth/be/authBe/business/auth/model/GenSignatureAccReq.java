package com.auth.be.authBe.business.auth.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class GenSignatureAccReq {
    private String clientId;
    private String privateKey;
    private String timestamp;
}