package com.myspringsecurity.jwt.myapp.domain;

public class Book {

    private final Integer bookId;
    private final String bookName;

    public Book(Integer bookId,
                   String bookName) {
        this.bookId = bookId;
        this.bookName = bookName;
    }

    public Integer getBookId() {
        return bookId;
    }

    public String getBookName() {
        return bookName;
    }

    @Override
    public String toString() {
        return "Book{" +
                "bookId=" + bookId +
                ", bookName='" + bookName + '\'' +
                '}';
    }
}
