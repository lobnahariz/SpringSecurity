package com.lobna.security.user;

import lombok.Getter;

public enum Permission {

    ADMIN_READ("admin:read"),
    ADMIN_UPDATE("admin:update"),
    ADMIN_DELETE("admin:delete"),
    ADMIN_CREATE("admin:create"),

    MANAGER_READ("manager:read"),
    MANAGER_UPDATE("manager:update"),
    MANAGER_DELETE("manager:delete"),
    MANAGER_CREATE("manager:create");

    @Getter
    private final String permission;

    Permission(String permission) {
        this.permission = permission;
    }
}
