//src/main/java/com/auth/api/repository/LoginAttemptRepository.java
package com.auth.api.repository;

import com.auth.api.model.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {
    Optional<LoginAttempt> findByEmail(String email);
}