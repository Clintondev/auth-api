//src/main/java/com/auth/api/controller/AuthController.java
package com.auth.api.controller;

import com.auth.api.model.AuditLog;
import com.auth.api.model.User;
import com.auth.api.model.AuthResponse;
import com.auth.api.model.LoginRequest;
import com.auth.api.model.RefreshToken;
import com.auth.api.model.PasswordResetToken;
import com.auth.api.repository.AuditLogRepository;
import com.auth.api.repository.UserRepository;
import com.auth.api.repository.LoginAttemptRepository;
import com.auth.api.repository.RefreshTokenRepository;
import com.auth.api.repository.PasswordResetTokenRepository;
import com.auth.api.service.EmailService;
import com.auth.api.service.RateLimitingService;
import com.auth.api.model.LoginAttempt;
import com.auth.api.security.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import com.auth.api.service.TwoFactorAuthService;
import org.springframework.security.access.prepost.PreAuthorize;
import io.github.bucket4j.Bucket;
import org.springframework.beans.factory.annotation.Autowired;

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

    @Autowired
    private TwoFactorAuthService twoFactorAuthService;

    @Autowired
    private RateLimitingService rateLimitingService;

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
        String clientIP = request.getRemoteAddr(); 
        Bucket bucket = rateLimitingService.resolveBucket(clientIP); 

        if (bucket.tryConsume(1)) {
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
                if (user.isTwoFactorEnabled()) {
                    int max2faAttempts = 5;
                    LoginAttempt twoFactorAttempt = loginAttemptRepository.findByEmail(email)
                            .orElseGet(() -> new LoginAttempt(email, 0, false));

                    if (loginRequest.getTwoFactorCode() == null) {
                        log.warn("Código 2FA necessário para o e-mail: {}", email);
                        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Código 2FA necessário.");
                    }

                    if (twoFactorAttempt.getAttempts() >= max2faAttempts) {
                        log.warn("Múltiplas tentativas de 2FA falhadas para o e-mail: {}", email);
                        return ResponseEntity.status(HttpStatus.LOCKED).body("Múltiplas tentativas de 2FA falhadas. Tente novamente mais tarde.");
                    }

                    boolean isCodeValid = twoFactorAuthService.verifyCode(user.getTwoFactorSecret(), loginRequest.getTwoFactorCode());
                    if (!isCodeValid) {
                        twoFactorAttempt.incrementAttempts();
                        loginAttemptRepository.save(twoFactorAttempt);
                        log.warn("Código 2FA inválido para o e-mail: {}", email);
                        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Código 2FA inválido.");
                    }
                    twoFactorAttempt.resetAttempts();
                    loginAttemptRepository.save(twoFactorAttempt);
                }

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
        } else {
            log.warn("Limite de tentativas excedido para o IP: {}", clientIP);
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body("Muitas tentativas de login. Tente novamente em 1 minuto.");
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
    @PreAuthorize("hasRole('ADMIN') or authentication.name == @userRepository.findById(#id).get().email")
    @PostMapping("/enable-2fa/{id}")
    public ResponseEntity<?> enableTwoFactorAuth(@PathVariable Long id) throws Exception {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        String secret = twoFactorAuthService.generateSecretKey();
        user.setTwoFactorSecret(secret);
        user.setTwoFactorEnabled(true);
        userRepository.save(user);

        String qrCode = twoFactorAuthService.generateQrCode(user.getEmail(), secret);

        return ResponseEntity.ok(Map.of(
            "message", "2FA habilitado com sucesso para o usuário: " + user.getEmail(),
            "qrCode", qrCode,
            "secret", secret
        ));
    }

    @PreAuthorize("hasRole('ADMIN') or authentication.name == @userRepository.findById(#id).get().email")    
    @DeleteMapping("/disable-2fa/{id}")
    public ResponseEntity<?> disableTwoFactorAuth(@PathVariable Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null);  
        userRepository.save(user);

        return ResponseEntity.ok("Autenticação de dois fatores desativada com sucesso para o usuário: " + user.getEmail());
    }

    @PreAuthorize("authentication.name == @userRepository.findById(#id).get().email")
    @GetMapping("/2fa-info/{id}")
    public ResponseEntity<?> getTwoFactorAuthInfo(@PathVariable Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        if (!user.isTwoFactorEnabled()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("2FA não está habilitado para este usuário.");
        }

        String qrCode;
        try {
            qrCode = twoFactorAuthService.generateQrCode(user.getEmail(), user.getTwoFactorSecret());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Erro ao gerar o QR Code.");
        }

        return ResponseEntity.ok(Map.of(
            "qrCode", qrCode,
            "secret", user.getTwoFactorSecret()
        ));
    }
}
