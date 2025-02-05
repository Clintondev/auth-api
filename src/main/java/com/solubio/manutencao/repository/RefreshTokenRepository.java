//src/main/java/com/solubio/manutencao/repository/RefreshTokenRepository.java
package com.solubio.manutencao.repository;

import com.solubio.manutencao.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    void deleteByUserId(Long userId);
}