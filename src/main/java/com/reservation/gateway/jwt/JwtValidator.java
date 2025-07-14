package com.reservation.gateway.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Component
public class JwtValidator {

    private final SecretKey secretKey;

    public JwtValidator(@Value("${jwt.secret}") String secret) {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public Claims validateToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("토큰이 만료되었습니다", e);
        } catch (JwtException e) {
            throw new RuntimeException("유효하지 않은 토큰입니다", e);
        }
    }

    public boolean isTokenValid(String token) {
        try {
            validateToken(token);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
