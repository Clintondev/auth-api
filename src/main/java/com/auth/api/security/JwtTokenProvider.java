//src/main/java/com/auth/api/security/JwtTokenProvider.java
package com.auth.api.security;

import com.auth.api.model.RefreshToken;
import com.auth.api.model.User;
import com.auth.api.repository.RefreshTokenRepository;
import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.UUID;

@Component
public class JwtTokenProvider {

    private final Dotenv dotenv = Dotenv.load();
    private final String secretKey = dotenv.get("JWT_SECRET_KEY");
    private final long accessTokenExpiration = 900_000;  // 15 minutos
    private final long refreshTokenExpiration = 7 * 24 * 60 * 60 * 1000;  // 7 dias

    private final RefreshTokenRepository refreshTokenRepository;

    public JwtTokenProvider(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public String generateAccessToken(User user) {
        return io.jsonwebtoken.Jwts.builder()
                .setSubject(user.getEmail())
                .setIssuedAt(new java.util.Date())
                .setExpiration(new java.util.Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(io.jsonwebtoken.SignatureAlgorithm.HS256, secretKey.getBytes())
                .compact();
    }

    public RefreshToken generateRefreshToken(User user) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(LocalDateTime.now().plusDays(7));
        refreshToken.setRevoked(false);
        return refreshTokenRepository.save(refreshToken);
    }

    public boolean validateToken(String token) {
        try {
            io.jsonwebtoken.Jwts.parser().setSigningKey(secretKey.getBytes()).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String extractEmail(String token) {
        return io.jsonwebtoken.Jwts.parser()
                .setSigningKey(secretKey.getBytes())
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}