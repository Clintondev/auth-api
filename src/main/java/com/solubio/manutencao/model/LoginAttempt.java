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
}