package com.auth.be.authBe.auth.constant;

public class AuthConstant {
    public static final String AUTH_TYPE_SNAP = "SNAP";
    public static final String AUTH_TYPE_BASIC = "BASIC";
    public static final String TOKEN_TYPE_BEARER = "BEARER";
    public static final String TOKEN_TYPE_BEARERWTOKEN = "BEARERWPREFIX";
    public static final String TOKEN_TYPE_MAC = "MAC";
    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String INVALID_GRANT_TYPE = "invalid_grant";
    public static final String ACCESS_TOKEN_BODY_REQUEST = "{\"grant_type\":\"client_credentials\"}";

    private AuthConstant() {}
}
