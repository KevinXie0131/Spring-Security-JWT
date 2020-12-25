package com.myspringsecurity.jwt.myapp.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

public enum ApplicationUserRole {
    READER(Sets.newHashSet(ApplicationUserPermission.BOOK_READ)),
    ADMIN(Sets.newHashSet(ApplicationUserPermission.BOOK_READ, ApplicationUserPermission.BOOK_ADD, ApplicationUserPermission.BOOK_DELETE)),
    MANAGER(Sets.newHashSet(ApplicationUserPermission.BOOK_ADD, ApplicationUserPermission.BOOK_DELETE, ApplicationUserPermission.INVENTORY_LIST));

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permissions;
    }
}
