package com.auth.be.authBe.auth;

import java.time.LocalDateTime;

import com.auth.be.authBe.auth.constant.AuthConstant;
import com.auth.be.authBe.exception.BadRequestException;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@Table(name = "auth")
@NoArgsConstructor
@AllArgsConstructor
@IdClass(AuthEntityId.class)
public class AuthEntity {
    @Id
    @Column(name = "channel_id", nullable = false)
    private String channelId;

    @Id
    @Column(name = "auth_type", nullable = false)
    private String authType;

    @Column(name = "token_type")
    private String tokenType;

    @Column(name = "client_key")
    private String clientKey;

    @Column(name = "client_secret")
    private String clientSecret;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    @Column(name = "public_key")
    private String publicKey;

    @Column(name = "private_key", length = 500)
    private String privateKey;

    @Column(name = "access_token_expiry_time")
    private Integer accessTokenExpiryTime;

    @Column(name = "refresh_token_expiry_time")
    private Integer refreshTokenExpiryTime;

    @Column(name = "status", nullable = false)
    private String status;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    public void validateSave() {
        if (this.channelId == null || this.channelId.isEmpty() || this.authType == null || this.authType.isEmpty()) {
            throw new BadRequestException("Channel name cannot be null or empty");
        }
        if (this.status == null || this.status.isEmpty()) {
            throw new BadRequestException("Status cannot be null or empty");
        }
        if (!this.status.equals("1") && !this.status.equals("0")) {
            throw new BadRequestException("Status must be 1 or 0");
        }
        if (this.authType.equals(AuthConstant.AUTH_TYPE_SNAP)) {
            if (this.tokenType == null || this.tokenType.isEmpty()) {
                throw new BadRequestException("Token type cannot be null or empty");
            }
            if (!this.tokenType.equals(AuthConstant.TOKEN_TYPE_BEARER)
                    && !this.tokenType.equals(AuthConstant.TOKEN_TYPE_BEARERWTOKEN)) {
                throw new BadRequestException("Token type must be BEARER, BEARERWPREFIX");
            }
            if (this.clientKey == null || this.clientKey.isEmpty() || this.clientSecret == null
                    || this.clientSecret.isEmpty()) {
                throw new BadRequestException("Client key and Client secret cannot be null or empty");
            }
            if (this.publicKey == null || this.publicKey.isEmpty() || this.privateKey == null
                    || this.privateKey.isEmpty()) {
                throw new BadRequestException("Public key and Private key cannot be null or empty");
            }
            if (this.accessTokenExpiryTime == null) {
                throw new BadRequestException("Access token expiry cannot be null or empty");
            }
            // if (this.accessTokenExpiryTime > 0) {
            //     throw new BadRequestException("Access token expiry must be greater than 0");
            // }
        } else if (this.authType.equals(AuthConstant.AUTH_TYPE_BASIC)) {
            if (this.username == null || this.username.isEmpty() || this.password == null || this.password.isEmpty()) {
                throw new BadRequestException("Username and Password cannot be null or empty");
            }
            if (this.accessTokenExpiryTime == null || this.refreshTokenExpiryTime == null) {
                throw new BadRequestException("Access token expiry and Refresh token expiry cannot be null or empty");
            }
            // if (this.accessTokenExpiryTime > 0 || this.refreshTokenExpiryTime > 0) {
            //     throw new BadRequestException("Access token expiry and Refresh token expiry must be greater than 0");
            // }
        } else {
            throw new BadRequestException("Auth type must be SNAP or BASIC");
        }
    }
}
