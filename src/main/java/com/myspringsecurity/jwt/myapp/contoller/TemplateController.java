package com.myspringsecurity.jwt.myapp.contoller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class TemplateController {

    @GetMapping("")
    public String root() {
        return "redirect:/login";
    }

    @GetMapping("login")
    public String getLogin() {
        return "login";
    }

    @GetMapping("bookstore")
    @PreAuthorize("hasAnyRole('ROLE_READER')")
    public String getBookstore() {
        return "bookstore";
    }

    @GetMapping("bookstoreadmin")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_MANAGER')")
    public String getBookstoreAdmin() {
        return "bookstoreadmin";
    }

    @GetMapping("/403")
    public String accesssDenied() {
        return "403";
    }
}
