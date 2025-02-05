//src/main/java/com/solubio/manutencao/controller/AuthController.java
package com.solubio.manutencao.controller;

import com.solubio.manutencao.model.AuditLog;
import com.solubio.manutencao.model.User;
import com.solubio.manutencao.model.AuthResponse;
import com.solubio.manutencao.model.LoginRequest;
import com.solubio.manutencao.model.RefreshToken;
import com.solubio.manutencao.model.PasswordResetToken;
import com.solubio.manutencao.repository.AuditLogRepository;
import com.solubio.manutencao.repository.UserRepository;
import com.solubio.manutencao.repository.LoginAttemptRepository;
import com.solubio.manutencao.repository.RefreshTokenRepository;
import com.solubio.manutencao.repository.PasswordResetTokenRepository;
import com.solubio.manutencao.service.EmailService;
import com.solubio.manutencao.model.LoginAttempt;
import com.solubio.manutencao.security.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
@Slf4j
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private LoginAttemptRepository loginAttemptRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    private EmailService emailService;

    @Autowired
    private HttpServletRequest request;

    private void logAudit(String action, String userEmail) {
        AuditLog auditLog = new AuditLog();
        auditLog.setUserEmail(userEmail);
        auditLog.setAction(action);
        auditLog.setEntity("Authentication");
        auditLog.setIpAddress(request.getRemoteAddr());
        auditLog.setUserAgent(request.getHeader("User-Agent"));
        auditLogRepository.save(auditLog);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        log.info("Tentativa de login para o e-mail: {}", loginRequest.getEmail());

        String email = loginRequest.getEmail();
        LoginAttempt attempt = loginAttemptRepository.findByEmail(email)
                .orElseGet(() -> new LoginAttempt(email, 0, false));

        if (attempt.isLocked()) {
            log.warn("Conta bloqueada para o e-mail: {}", email);
            return ResponseEntity.status(HttpStatus.LOCKED).body("Conta bloqueada devido a múltiplas tentativas de login.");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    attempt.incrementAttempts();
                    if (attempt.getAttempts() >= 5) {
                        attempt.setLocked(true);
                    }
                    loginAttemptRepository.save(attempt);
                    log.warn("Tentativa de login falhou para o e-mail: {}", email);
                    logAudit("LOGIN_FAILED", email);
                    return new RuntimeException("Credenciais inválidas");
                });

        if (passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            attempt.resetAttempts();
            loginAttemptRepository.save(attempt);

            String accessToken = jwtTokenProvider.generateAccessToken(user);
            RefreshToken refreshToken = jwtTokenProvider.generateRefreshToken(user);

            log.info("Login bem-sucedido para o usuário: {}", user.getEmail());
            logAudit("LOGIN_SUCCESS", user.getEmail());

            return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken.getToken()));
        } else {
            attempt.incrementAttempts();
            if (attempt.getAttempts() >= 5) {
                attempt.setLocked(true);
            }
            loginAttemptRepository.save(attempt);
            log.warn("Senha inválida para o e-mail: {}", email);
            logAudit("LOGIN_FAILED", email);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciais inválidas");
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        RefreshToken tokenEntity = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Refresh Token não encontrado"));

        if (tokenEntity.isRevoked() || tokenEntity.getExpiryDate().isBefore(LocalDateTime.now())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh Token expirado ou revogado");
        }

        User user = tokenEntity.getUser();
        String newAccessToken = jwtTokenProvider.generateAccessToken(user);
        return ResponseEntity.ok(new AuthResponse(newAccessToken, refreshToken));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> request) {
        String refreshTokenRequest = request.get("refreshToken");

        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenRequest)
                .orElseThrow(() -> new RuntimeException("Refresh Token inválido"));

        refreshToken.setRevoked(true);
        refreshTokenRepository.save(refreshToken);

        return ResponseEntity.ok("Logout realizado com sucesso.");
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado."));

        String token = UUID.randomUUID().toString();

        PasswordResetToken resetToken = passwordResetTokenRepository.findByUser(user)
                .orElseGet(() -> new PasswordResetToken());

        resetToken.setToken(token);
        resetToken.setUser(user);
        resetToken.setExpiryDate(LocalDateTime.now().plusHours(1));
        passwordResetTokenRepository.save(resetToken);

        emailService.sendPasswordResetEmail(user.getEmail(), token);
        return ResponseEntity.ok("E-mail de redefinição de senha enviado.");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        String newPassword = request.get("newPassword");

        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Token inválido ou expirado."));

        if (resetToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token expirado.");
        }

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        passwordResetTokenRepository.delete(resetToken);

        return ResponseEntity.ok("Senha redefinida com sucesso.");
    }
}
