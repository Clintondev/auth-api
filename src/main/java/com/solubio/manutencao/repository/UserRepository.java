//src/main/java/com/solubio/manutencao/repository/UserRepository.java
package com.solubio.manutencao.repository;

import com.solubio.manutencao.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
}