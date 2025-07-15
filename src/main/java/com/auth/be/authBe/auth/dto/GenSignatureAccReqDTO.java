package com.auth.be.authBe.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class GenSignatureAccReqDTO {
    private String clientId;
    private String privateKey;
    private String timestamp;
}