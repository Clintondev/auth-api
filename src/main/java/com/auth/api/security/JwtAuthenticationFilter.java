//src/main/java/com/auth/api/security/JwtAuthenticationFilter.java
package com.auth.api.security;

import com.auth.api.repository.RevokedTokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.github.cdimascio.dotenv.Dotenv;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final UserDetailsService userDetailsService;
    private final RevokedTokenRepository revokedTokenRepository;
    private final Dotenv dotenv = Dotenv.load();
    private final String secretKey = dotenv.get("JWT_SECRET_KEY");

    public JwtAuthenticationFilter(UserDetailsService userDetailsService, RevokedTokenRepository revokedTokenRepository) {
        this.userDetailsService = userDetailsService;
        this.revokedTokenRepository = revokedTokenRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String token = authHeader.substring(7);

        // Check if the token is revoked
        if (revokedTokenRepository.existsByToken(token)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Token revogado. Faça login novamente.");
            return;
        }

        final String email = extractEmail(token);

        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);

            if (validateToken(token, userDetails)) {
                Claims claims = Jwts.parser()
                        .setSigningKey(secretKey.getBytes())
                        .parseClaimsJws(token)
                        .getBody();
                List<String> tokenRoles = claims.get("roles") != null
                    ? ((List<?>) claims.get("roles"))
                        .stream()
                        .filter(role -> role instanceof String)
                        .map(role -> ((String) role).toUpperCase(Locale.ROOT))
                        .collect(Collectors.toList())
                    : List.of();  

                List<String> userRoles = userDetails.getAuthorities()
                        .stream()
                        .map(auth -> auth.getAuthority().replace("ROLE_", "").toUpperCase(Locale.ROOT))
                        .collect(Collectors.toList());

                if (!userRoles.containsAll(tokenRoles)) {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.getWriter().write("Token inválido: roles não correspondem aos do banco de dados.");
                    return;
                }

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractEmail(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(secretKey.getBytes())
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    private boolean validateToken(String token, UserDetails userDetails) {
        try {
            final String email = extractEmail(token);
            return email.equals(userDetails.getUsername()) && !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        final Date expiration = Jwts.parser()
                .setSigningKey(secretKey.getBytes())
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
        return expiration.before(new Date());
    }
}