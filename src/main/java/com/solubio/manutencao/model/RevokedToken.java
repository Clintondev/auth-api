//src/main/java/com/solubio/manutencao/model/RevokedToken.java
package com.solubio.manutencao.model;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Data
public class RevokedToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token;

    private LocalDateTime revokedAt;
}