//src/main/java/com/solubio/manutencao/repository/RevokedTokenRepository.java
package com.solubio.manutencao.repository;

import com.solubio.manutencao.model.RevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RevokedTokenRepository extends JpaRepository<RevokedToken, Long> {
    Optional<RevokedToken> findByToken(String token);
    boolean existsByToken(String token);
}