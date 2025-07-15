package com.auth.be.authBe.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SnapAccessTokenResDTO {
    private String accessToken;
    private String tokenType;
    private Integer expiresIn;
}
