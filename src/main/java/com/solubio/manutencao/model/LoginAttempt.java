//src/main/java/com/solubio/manutencao/model/LoginAttempt.java
package com.solubio.manutencao.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Entity
@Data
public class LoginAttempt {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String email;
    private int attempts;
    private LocalDateTime lastAttempt;
    private boolean locked;

    // Construtor personalizado
    public LoginAttempt(String email, int attempts, boolean locked) {
        this.email = email;
        this.attempts = attempts;
        this.locked = locked;
        this.lastAttempt = LocalDateTime.now();
    }

    // Construtor vazio necessário para o JPA
    public LoginAttempt() {
        this.lastAttempt = LocalDateTime.now();
    }

    // Método para incrementar tentativas
    public void incrementAttempts() {
        this.attempts++;
        this.lastAttempt = LocalDateTime.now();
    }

    // Método para resetar tentativas
    public void resetAttempts() {
        this.attempts = 0;
        this.lastAttempt = LocalDateTime.now();
    }
}