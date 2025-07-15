package com.auth.be.authBe.auth.dto;

import com.auth.be.authBe.auth.constant.AuthConstant;
import com.auth.be.authBe.exception.BadRequestException;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AccessTokenBasicReqDTO {
    private String grant_type;
    private String refresh_token;

    public void validate() {
        if (this.grant_type == null || this.grant_type.isEmpty()) {
            throw new BadRequestException("Grant type cannot be null or empty");
        }
        if (this.grant_type.equals(AuthConstant.REFRESH_TOKEN) && (this.refresh_token == null || this.refresh_token.isEmpty())) {
            throw new BadRequestException("Refresh token cannot be null or empty");
        }
        log.debug("grant_type: {}", this.grant_type.equals(AuthConstant.CLIENT_CREDENTIALS));
        log.debug("grant_type: {}", this.grant_type.equals(AuthConstant.REFRESH_TOKEN));
        if (!this.grant_type.equals(AuthConstant.CLIENT_CREDENTIALS) && !this.grant_type.equals(AuthConstant.REFRESH_TOKEN)) {
            if (this.grant_type.equals(AuthConstant.INVALID_GRANT_TYPE)) {
                throw new BadRequestException("Invalid grant type");
            } 
            throw new BadRequestException("Grant type must be client_credentials or refresh_token");
        }
        
        
    }
}
