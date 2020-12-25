package com.myspringsecurity.jwt.myapp.security;

public enum ApplicationUserPermission {
    BOOK_READ("book:read"),
    BOOK_ADD("book:add"),
    BOOK_DELETE("book:delete"),
    INVENTORY_LIST("inventory:list");

    private final String permission;

    ApplicationUserPermission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}
