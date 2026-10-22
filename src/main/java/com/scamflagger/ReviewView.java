package com.scamflagger;

import java.time.LocalDateTime;

public record ReviewView(
        long id,
        long userId,
        long websiteId,
        int rating,
        String comment,
        LocalDateTime createdAt,
        String username) {
}
