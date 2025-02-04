//src/main/java/com/solubio/manutencao/service/AuditService.java
package com.solubio.manutencao.service;

import com.solubio.manutencao.model.AuditLog;
import com.solubio.manutencao.repository.AuditLogRepository;
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