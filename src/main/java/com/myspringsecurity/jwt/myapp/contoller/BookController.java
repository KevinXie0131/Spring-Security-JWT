package com.myspringsecurity.jwt.myapp.contoller;

import com.myspringsecurity.jwt.myapp.domain.Book;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/book")
public class BookController {

    private static final List<Book> Books = Arrays.asList(
      new Book(1, "Think in Java"),
      new Book(2, "Effective Java"),
      new Book(3, "Core Java")
    );

    @GetMapping(path = "{bookId}")
    public Book getBook(@PathVariable("bookId") Integer bookId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return Books.stream()
                .filter(book -> bookId.equals(book.getBookId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "Book " + bookId + " does not exists"
                ));
    }
}
