package com.api.login.Repository;

import java.util.Optional;

import com.api.login.models.ERole;
import com.api.login.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleRepo extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}