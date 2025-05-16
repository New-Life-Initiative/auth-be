package com.auth.be.authBe.auth;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthRepository extends JpaRepository<AuthEntity, AuthEntityId> {
    AuthEntity findByChannelIdAndAuthType(String channelId, String authType);

    AuthEntity findByClientKey(String clientKey);
}
