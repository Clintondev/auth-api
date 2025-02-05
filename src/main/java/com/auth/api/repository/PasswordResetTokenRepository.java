//src/main/java/com/auth/api/repository/PasswordResetTokenRepository.java
package com.auth.api.repository;

import com.auth.api.model.PasswordResetToken;
import com.auth.api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByToken(String token);
    Optional<PasswordResetToken> findByUser(User user);
}