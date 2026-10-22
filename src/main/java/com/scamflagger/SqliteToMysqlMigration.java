package com.scamflagger;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ParameterizedPreparedStatementSetter;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;

@Component
@ConditionalOnProperty(name = "app.migrate-sqlite-from")
public class SqliteToMysqlMigration implements ApplicationRunner {
    private static final Logger logger = LoggerFactory.getLogger(SqliteToMysqlMigration.class);
    private static final int BATCH_SIZE = 500;

    private final JdbcTemplate mysql;
    private final TransactionTemplate transaction;
    private final Environment environment;

    public SqliteToMysqlMigration(JdbcTemplate mysql, PlatformTransactionManager transactionManager,
                                  Environment environment) {
        this.mysql = mysql;
        this.transaction = new TransactionTemplate(transactionManager);
        this.environment = environment;
    }

    @Override
    public void run(ApplicationArguments arguments) throws Exception {
        if (!environment.acceptsProfiles(Profiles.of("mysql"))) {
            throw new IllegalArgumentException("SQLite migration requires the mysql Spring profile");
        }
        String configuredPath = arguments.getOptionValues("app.migrate-sqlite-from").getFirst();
        Path sourcePath = Path.of(configuredPath).toAbsolutePath().normalize();
        if (!java.nio.file.Files.isRegularFile(sourcePath)) {
            throw new IllegalArgumentException("SQLite source database does not exist: " + sourcePath);
        }

        int[] counts = transaction.execute(status -> {
            try (Connection sqlite = DriverManager.getConnection("jdbc:sqlite:" + sourcePath)) {
                validateSource(sqlite);
                int users = copyUsers(sqlite);
                int websites = copyWebsites(sqlite);
                int reviews = copyReviews(sqlite);
                return new int[]{users, websites, reviews};
            } catch (SQLException exception) {
                throw new IllegalStateException("Could not read the SQLite source database", exception);
            }
        });
        logger.info("SQLite migration completed: {} users, {} websites, {} reviews",
                counts[0], counts[1], counts[2]);
    }

    private static void validateSource(Connection sqlite) throws SQLException {
        try (var statement = sqlite.createStatement();
             ResultSet result = statement.executeQuery("""
                     SELECT
                         (SELECT COUNT(*) FROM users WHERE length(username) > 80 OR length(email) > 254)
                         + (SELECT COUNT(*) FROM websites WHERE length(url) > 700)
                     """)) {
            if (result.next() && result.getLong(1) > 0) {
                throw new IllegalStateException(
                        "SQLite contains usernames, emails, or URLs exceeding MySQL schema limits; "
                                + "shorten those values before migration");
            }
        }
    }

    private int copyUsers(Connection sqlite) throws SQLException {
        List<Object[]> rows = new ArrayList<>();
        try (var statement = sqlite.createStatement();
             ResultSet result = statement.executeQuery(
                     "SELECT id, username, email, password_hash, created_at FROM users")) {
            while (result.next()) {
                rows.add(new Object[]{result.getLong("id"), result.getString("username"),
                        result.getString("email"), result.getString("password_hash"),
                        readTimestamp(result, "created_at")});
            }
        }
        mysql.batchUpdate("""
                INSERT INTO users (id, username, email, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE username = VALUES(username), email = VALUES(email),
                    password_hash = VALUES(password_hash), created_at = VALUES(created_at)
                """, rows, BATCH_SIZE, bindUser());
        return rows.size();
    }

    private int copyWebsites(Connection sqlite) throws SQLException {
        List<Object[]> rows = new ArrayList<>();
        try (var statement = sqlite.createStatement();
             ResultSet result = statement.executeQuery(
                     "SELECT id, url, risk_score, flagged, created_at, last_checked FROM websites")) {
            while (result.next()) {
                rows.add(new Object[]{result.getLong("id"), result.getString("url"),
                        result.getInt("risk_score"), result.getBoolean("flagged"),
                        readTimestamp(result, "created_at"), readTimestamp(result, "last_checked")});
            }
        }
        mysql.batchUpdate("""
                INSERT INTO websites (id, url, risk_score, flagged, created_at, last_checked)
                VALUES (?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE url = VALUES(url), risk_score = VALUES(risk_score),
                    flagged = VALUES(flagged), created_at = VALUES(created_at),
                    last_checked = VALUES(last_checked)
                """, rows, BATCH_SIZE, bindWebsite());
        return rows.size();
    }

    private int copyReviews(Connection sqlite) throws SQLException {
        List<Object[]> rows = new ArrayList<>();
        try (var statement = sqlite.createStatement();
             ResultSet result = statement.executeQuery(
                     "SELECT id, user_id, website_id, rating, comment, created_at FROM reviews")) {
            while (result.next()) {
                rows.add(new Object[]{result.getLong("id"), result.getLong("user_id"),
                        result.getLong("website_id"), result.getInt("rating"),
                        result.getString("comment"), readTimestamp(result, "created_at")});
            }
        }
        mysql.batchUpdate("""
                INSERT INTO reviews (id, user_id, website_id, rating, comment, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE user_id = VALUES(user_id), website_id = VALUES(website_id),
                    rating = VALUES(rating), comment = VALUES(comment), created_at = VALUES(created_at)
                """, rows, BATCH_SIZE, bindReview());
        return rows.size();
    }

    private static Timestamp readTimestamp(ResultSet result, String column) throws SQLException {
        String value = result.getString(column);
        if (value == null) {
            return null;
        }
        return Timestamp.valueOf(value.replace(' ', 'T'));
    }

    private static ParameterizedPreparedStatementSetter<Object[]> bindUser() {
        return (statement, row) -> {
            statement.setLong(1, (Long) row[0]);
            statement.setString(2, (String) row[1]);
            statement.setString(3, (String) row[2]);
            statement.setString(4, (String) row[3]);
            statement.setTimestamp(5, (Timestamp) row[4]);
        };
    }

    private static ParameterizedPreparedStatementSetter<Object[]> bindWebsite() {
        return (statement, row) -> {
            statement.setLong(1, (Long) row[0]);
            statement.setString(2, (String) row[1]);
            statement.setInt(3, (Integer) row[2]);
            statement.setBoolean(4, (Boolean) row[3]);
            statement.setTimestamp(5, (Timestamp) row[4]);
            statement.setTimestamp(6, (Timestamp) row[5]);
        };
    }

    private static ParameterizedPreparedStatementSetter<Object[]> bindReview() {
        return (statement, row) -> {
            statement.setLong(1, (Long) row[0]);
            statement.setLong(2, (Long) row[1]);
            statement.setLong(3, (Long) row[2]);
            statement.setInt(4, (Integer) row[3]);
            statement.setString(5, (String) row[4]);
            statement.setTimestamp(6, (Timestamp) row[5]);
        };
    }
}
