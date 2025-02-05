//src/main/java/com/auth/api/controller/UsersController.java
package com.auth.api.controller;

import com.auth.api.model.AuditLog;
import com.auth.api.model.Role;
import com.auth.api.model.User;
import com.auth.api.service.UserService;
import com.auth.api.repository.AuditLogRepository;
import com.auth.api.repository.RoleRepository;
import com.auth.api.service.AuditService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import jakarta.servlet.http.HttpServletRequest;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/users")
@Slf4j
public class UsersController {

    @Autowired
    private UserService userService;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private HttpServletRequest request;

    @Autowired
    private AuditService auditService;

    private void logAudit(String action, String entity, Long entityId) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        auditService.logAudit(action, entity, entityId, getCurrentUserEmail(), ipAddress, userAgent);
    }

    private String getCurrentUserEmail() {
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'PCM', 'COORDENADOR')")
    @PostMapping("/create")
    public ResponseEntity<?> createUser(@RequestBody User user) {
        String currentUserEmail = getCurrentUserEmail();
        log.info("Usuário {} tentando criar um novo usuário: {}", currentUserEmail, user.getEmail());

        if (userService.findByEmail(user.getEmail()).isPresent()) {
            log.warn("Tentativa de criar usuário com e-mail já existente: {}", user.getEmail());
            return ResponseEntity.badRequest().body("E-mail já está em uso.");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        if (user.getRoles() != null && !user.getRoles().isEmpty()) {
            Set<Role> validRoles = user.getRoles().stream()
                    .map(role -> roleRepository.findByName(role.getName()))
                    .filter(role -> role != null)
                    .collect(Collectors.toSet());

            if (validRoles.isEmpty()) {
                return ResponseEntity.badRequest().body("Nenhuma role válida foi fornecida.");
            }
            user.setRoles(validRoles);
        } else {
            Role defaultRole = roleRepository.findByName("SOLICITANTE");
            user.setRoles(Set.of(defaultRole));
        }

        userService.save(user);
        log.info("Usuário {} criado com sucesso pelo usuário {}", user.getEmail(), currentUserEmail);
        logAudit("CREATE", "User", user.getId());
        return ResponseEntity.ok("Usuário criado com sucesso.");
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'PCM', 'COORDENADOR')")
    @PutMapping("/update/{id}")
    public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody User updatedUser) {
        String currentUserEmail = getCurrentUserEmail();
        log.info("Usuário {} tentando atualizar o usuário ID: {}", currentUserEmail, id);

        Optional<User> optionalUser = userService.findById(id);
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            user.setNome(updatedUser.getNome());
            user.setEmail(updatedUser.getEmail());
            userService.save(user);
            log.info("Usuário ID: {} atualizado com sucesso por {}", id, currentUserEmail);
            logAudit("UPDATE", "User", user.getId());
            return ResponseEntity.ok("Usuário atualizado com sucesso.");
        } else {
            log.warn("Tentativa de atualização falhou. Usuário ID: {} não encontrado.", id);
            return ResponseEntity.notFound().build();
        }
    }

    @PreAuthorize("hasAnyRole('ADMIN', 'PCM', 'COORDENADOR')")
    @DeleteMapping("/delete/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        String currentUserEmail = getCurrentUserEmail();
        log.info("Usuário {} tentando deletar o usuário ID: {}", currentUserEmail, id);

        if (userService.existsById(id)) {
            userService.deleteById(id);
            log.info("Usuário ID: {} deletado com sucesso por {}", id, currentUserEmail);
            logAudit("DELETE", "User", id);
            return ResponseEntity.ok("Usuário deletado com sucesso.");
        } else {
            log.warn("Tentativa de exclusão falhou. Usuário ID: {} não encontrado.", id);
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/list")
    public List<User> listAllUsers() {
        log.info("Listagem de todos os usuários solicitada por {}", getCurrentUserEmail());
        return userService.findAll().stream()
                .map(user -> {
                    user.setPassword(null);
                    return user;
                })
                .collect(Collectors.toList());
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getUserById(@PathVariable Long id) {
        log.info("Usuário {} solicitou detalhes do usuário ID: {}", getCurrentUserEmail(), id);
        Optional<User> user = userService.findById(id);
        return user.map(u -> {
            u.setPassword(null);
            return ResponseEntity.ok(u);
        }).orElseGet(() -> {
            log.warn("Usuário ID: {} não encontrado.", id);
            return ResponseEntity.notFound().build();
        });
    }
}
