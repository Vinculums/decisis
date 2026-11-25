package com.shop.db;

public class Pool {
    public static class Conn {}

    public static Conn open() {
        return new Conn();
    }
}
