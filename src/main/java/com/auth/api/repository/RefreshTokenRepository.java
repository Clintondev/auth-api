//src/main/java/com/auth/api/repository/RefreshTokenRepository.java
package com.auth.api.repository;

import com.auth.api.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    void deleteByUserId(Long userId);
}