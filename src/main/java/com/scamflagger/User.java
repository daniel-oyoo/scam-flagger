package com.scamflagger;

public record User(long id, String username, String email, String passwordHash) {
}
