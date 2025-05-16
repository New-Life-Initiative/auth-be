package com.auth.be.authBe.auth;

import java.time.LocalDateTime;

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
    private Long accessTokenExpiryTime;

    @Column(name = "refresh_token_expiry_time")
    private Long refreshTokenExpiryTime;

    @Column(name = "status", nullable = false)
    private String status;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
}
