//src/main/java/com/solubio/manutencao/repository/RoleRepository.java
package com.solubio.manutencao.repository;

import com.solubio.manutencao.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}