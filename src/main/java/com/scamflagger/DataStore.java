package com.scamflagger;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class DataStore {
    private final JdbcTemplate jdbc;

    public DataStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<User> findUserByUsername(String username) {
        return jdbc.query(
                "SELECT id, username, email, password_hash FROM users WHERE username = ?",
                (rs, row) -> new User(rs.getLong("id"), rs.getString("username"),
                        rs.getString("email"), rs.getString("password_hash")),
                username).stream().findFirst();
    }

    public boolean createUser(String username, String email, String passwordHash) {
        try {
            return jdbc.update(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    username, email, passwordHash) > 0;
        } catch (DataAccessException exception) {
            boolean duplicate = jdbc.queryForObject(
                    "SELECT COUNT(*) FROM users WHERE username = ? OR email = ?",
                    Integer.class, username, email) > 0;
            if (duplicate) {
                return false;
            }
            throw exception;
        }
    }

    public Optional<Website> findWebsiteByUrl(String url) {
        return jdbc.query(
                "SELECT id, url, risk_score, flagged, created_at, last_checked FROM websites WHERE url = ?",
                (rs, row) -> mapWebsite(rs.getLong("id"), rs.getString("url"),
                        rs.getInt("risk_score"), rs.getBoolean("flagged"),
                        rs.getString("created_at"), rs.getString("last_checked")),
                url).stream().findFirst();
    }

    public Optional<Website> findWebsiteById(long id) {
        return jdbc.query(
                "SELECT id, url, risk_score, flagged, created_at, last_checked FROM websites WHERE id = ?",
                (rs, row) -> mapWebsite(rs.getLong("id"), rs.getString("url"),
                        rs.getInt("risk_score"), rs.getBoolean("flagged"),
                        rs.getString("created_at"), rs.getString("last_checked")),
                id).stream().findFirst();
    }

    public Website saveWebsiteAnalysis(String url, int riskScore) {
        int updated = jdbc.update("""
                UPDATE websites SET risk_score = ?, flagged = ?, last_checked = CURRENT_TIMESTAMP
                WHERE url = ?
                """, riskScore, riskScore >= 70, url);
        if (updated == 0) {
            try {
                jdbc.update("INSERT INTO websites (url, risk_score, flagged) VALUES (?, ?, ?)",
                        url, riskScore, riskScore >= 70);
            } catch (DataAccessException exception) {
                updated = jdbc.update("""
                        UPDATE websites SET risk_score = ?, flagged = ?, last_checked = CURRENT_TIMESTAMP
                        WHERE url = ?
                        """, riskScore, riskScore >= 70, url);
                if (updated == 0) {
                    throw exception;
                }
            }
        }
        return findWebsiteByUrl(url).orElseThrow(
                () -> new IllegalStateException("Website was saved but could not be loaded"));
    }

    public List<ReviewView> findReviews(long websiteId) {
        return jdbc.query("""
                SELECT r.id, r.user_id, r.website_id, r.rating, r.comment, r.created_at, u.username
                FROM reviews r JOIN users u ON r.user_id = u.id
                WHERE r.website_id = ? ORDER BY r.created_at DESC
                """, (rs, row) -> new ReviewView(
                rs.getLong("id"), rs.getLong("user_id"), rs.getLong("website_id"),
                rs.getInt("rating"), rs.getString("comment"),
                LocalDateTime.parse(rs.getString("created_at").replace(' ', 'T')),
                rs.getString("username")), websiteId);
    }

    public void createReview(long userId, long websiteId, int rating, String comment) {
        jdbc.update("INSERT INTO reviews (user_id, website_id, rating, comment) VALUES (?, ?, ?, ?)",
                userId, websiteId, rating, comment);
    }

    private static Website mapWebsite(long id, String url, int riskScore, boolean flagged,
                                       String createdAt, String lastChecked) {
        return new Website(id, url, riskScore, flagged, parseDate(createdAt), parseDate(lastChecked));
    }

    private static LocalDateTime parseDate(String value) {
        return value == null ? null : LocalDateTime.parse(value.replace(' ', 'T'));
    }
}
