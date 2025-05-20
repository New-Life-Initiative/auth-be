package com.auth.be.authBe.auth.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AccessTokenBasicReqDTO {
    private String grant_type;
    private String refresh_token;
}
