//src/main/java/com/auth/api/repository/RevokedTokenRepository.java
package com.auth.api.repository;

import com.auth.api.model.RevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RevokedTokenRepository extends JpaRepository<RevokedToken, Long> {
    Optional<RevokedToken> findByToken(String token);
    boolean existsByToken(String token);
}