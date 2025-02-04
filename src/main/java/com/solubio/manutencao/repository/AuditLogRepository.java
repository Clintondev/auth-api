//src/main/java/com/solubio/manutencao/repository/AuditLogRepository.java
package com.solubio.manutencao.repository;

import com.solubio.manutencao.model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
}