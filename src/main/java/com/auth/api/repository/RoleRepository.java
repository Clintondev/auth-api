//src/main/java/com/auth/api/repository/RoleRepository.java
package com.auth.api.repository;

import com.auth.api.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}