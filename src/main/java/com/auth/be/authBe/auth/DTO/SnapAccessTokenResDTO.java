package com.auth.be.authBe.auth.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SnapAccessTokenResDTO {
    private String token;
    private Long activeToken;
}
