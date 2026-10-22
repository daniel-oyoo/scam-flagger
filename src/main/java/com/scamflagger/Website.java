package com.scamflagger;

import java.time.LocalDateTime;

public record Website(
        long id,
        String url,
        int riskScore,
        boolean flagged,
        LocalDateTime createdAt,
        LocalDateTime lastChecked) {
}
