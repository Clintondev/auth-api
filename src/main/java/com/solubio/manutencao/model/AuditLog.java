//src/main/java/com/solubio/manutencao/model/AuditLog.java
package com.solubio.manutencao.model;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Data
public class AuditLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String userEmail;
    private String action; 
    private String entity;
    private Long entityId;
    private String ipAddress;      
    private String userAgent;      
    private LocalDateTime timestamp = LocalDateTime.now();
}