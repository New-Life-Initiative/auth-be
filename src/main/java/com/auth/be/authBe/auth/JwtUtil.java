package com.auth.be.authBe.auth;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {
    public String extractUsername(String token, String Secret) {
        return extractClaim(token, Secret, Claims::getSubject);
    }

    public Date extractExpiration(String token, String Secret) {
        return extractClaim(token, Secret ,Claims::getExpiration);
    }

    public <T> T extractClaim(String token, String Secret, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token, Secret);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token, String Secret) {
        return Jwts
        //TODO: Cari tau kegunaan claims
                .parserBuilder()
                .setSigningKey(getSignKey(Secret))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token, String Secret) {
        return extractExpiration(token, Secret).before(new Date());
    }

    public Boolean validateToken(String token, String username, String Secret) {
        final String extractedUsername = extractUsername(token, Secret);
        return (extractedUsername.equals(username) && !isTokenExpired(token, Secret));
    }

    public String generateToken(String username, long jwtExpiration, String Secret) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username, jwtExpiration, Secret);
    }

    private String createToken(Map<String, Object> claims, String username, long jwtExpiration, String Secret) {
        //TODO: Cari tau kegunaan claims
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(getSignKey(Secret), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key getSignKey(String secret) {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
