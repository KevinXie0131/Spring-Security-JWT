package com.myspringsecurity.jwt.myapp.contoller;

import com.myspringsecurity.jwt.myapp.domain.Book;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/book")
public class BookManagementController {

    private static final List<Book> Books = Arrays.asList(
            new Book(1, "Think in Java"),
            new Book(2, "Effective Java"),
            new Book(3, "Core Java")
    );

//    hasRole('ROLE_') hasAnyRole('ROLE_') hasAuthority('permission') hasAnyAuthority('permission')

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_MANAGER')")
    public List<Book> getAllBooks() {
        System.out.println("get All Books");
        return Books;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('book:add')")
    public void addNewBook(@RequestBody Book book) {
        System.out.println("add New Book");
        System.out.println(book);
    }

    @GetMapping(path = "/delete/{bookId}")
    @PreAuthorize("hasAuthority('book:delete')")
    public void deleteBook(@PathVariable("bookId") Integer bookId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("delete book");
        System.out.println(bookId);
    }

}
