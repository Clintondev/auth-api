//src/main/java/com/auth/api/repository/AuditLogRepository.java
package com.auth.api.repository;

import com.auth.api.model.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
}