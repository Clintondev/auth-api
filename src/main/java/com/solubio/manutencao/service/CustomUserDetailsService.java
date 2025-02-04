//src/main/java/com/solubio/manutencao/service/CustomUserDetailsService.java
package com.solubio.manutencao.service;

import com.solubio.manutencao.model.User;
import com.solubio.manutencao.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado"));

        if (user.getEmail() == null || user.getEmail().isEmpty()) {
            throw new IllegalArgumentException("O e-mail do usuário não pode ser nulo ou vazio.");
        }

        if (user.getPassword() == null || user.getPassword().isEmpty()) {
            throw new IllegalArgumentException("A senha do usuário não pode ser nula ou vazia.");
        }

        String[] roles = user.getRoles().stream()
                .map(role -> role.getName())
                .filter(roleName -> roleName != null && !roleName.isEmpty()) 
                .toArray(String[]::new);

        if (roles.length == 0) {
            roles = new String[]{"USER"};
        }

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPassword())
                .roles(roles)
                .build();
    }
}