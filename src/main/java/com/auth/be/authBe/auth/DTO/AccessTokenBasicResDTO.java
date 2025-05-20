package com.auth.be.authBe.auth.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AccessTokenBasicResDTO {
    private String accessToken;
    private String refreshToken;
}
