//src/main/java/com/solubio/manutencao/repository/PasswordResetTokenRepository.java
package com.solubio.manutencao.repository;

import com.solubio.manutencao.model.PasswordResetToken;
import com.solubio.manutencao.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByToken(String token);
    Optional<PasswordResetToken> findByUser(User user);
}