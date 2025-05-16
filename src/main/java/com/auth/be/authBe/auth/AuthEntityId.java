package com.auth.be.authBe.auth;

import java.io.Serializable;
import java.util.Objects;

public class AuthEntityId implements Serializable {

    private String channelId;
    private String authType;

    public AuthEntityId() {
    }

    public AuthEntityId(String channelId, String authType) {
        this.channelId = channelId;
        this.authType = authType;
    }

    // equals and hashCode are required for IdClass to work properly

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof AuthEntityId))
            return false;
        AuthEntityId that = (AuthEntityId) o;
        return Objects.equals(channelId, that.channelId) &&
                Objects.equals(authType, that.authType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(channelId, authType);
    }

    // getters and setters (optional but recommended)
    public String getChannelId() {
        return channelId;
    }

    public void setChannelId(String channelId) {
        this.channelId = channelId;
    }

    public String getAuthType() {
        return authType;
    }

    public void setAuthType(String authType) {
        this.authType = authType;
    }
}
