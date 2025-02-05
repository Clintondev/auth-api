//src/main/java/com/auth/api/service/AuditService.java
package com.auth.api.service;

import com.auth.api.model.AuditLog;
import com.auth.api.repository.AuditLogRepository;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public AuditService(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @Async
    public void logAudit(String action, String entity, Long entityId, String userEmail, String ipAddress, String userAgent) {
        AuditLog auditLog = new AuditLog();
        auditLog.setAction(action);
        auditLog.setEntity(entity);
        auditLog.setEntityId(entityId);
        auditLog.setUserEmail(userEmail);
        auditLog.setIpAddress(ipAddress);  
        auditLog.setUserAgent(userAgent);  
        auditLogRepository.save(auditLog);
    }
}