//src/main/java/com/solubio/manutencao/repository/LoginAttemptRepository.java
package com.solubio.manutencao.repository;

import com.solubio.manutencao.model.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {
    Optional<LoginAttempt> findByEmail(String email);
}