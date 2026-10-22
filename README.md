# Scam Flagger

Scam Flagger is a Spring Boot web application for analyzing website risk and
sharing community reviews. The server-rendered pages use Thymeleaf. SQLite is
the local-development database; production uses MySQL when the `mysql` profile
is active. MySQL connections verify the server TLS certificate and hostname.

## Run locally

Requires Java 21 and Maven 3.9 or later.

```powershell
mvn spring-boot:run
```

Open <http://localhost:10000>. The application uses `scam_flagger.db` in the
working directory by default, preserving the existing SQLite database. Set
`DB_PATH` to use another database file and `PORT` to change the HTTP port.
Website analysis accepts public HTTP/HTTPS sites on the standard ports and
rejects private network hosts.

## Build and test

```powershell
mvn test
mvn package
```

## Deploy

The included Render Blueprint and Dockerfile build and run one Spring Boot
application with Java 21; MySQL is a separate managed service, not a second
process in the application container. Set the `MYSQL_HOST`, `MYSQL_DATABASE`, `MYSQL_USER`,
and `MYSQL_PASSWORD` environment variables in Render to the values from your
MySQL provider; `MYSQL_PORT` defaults to `3306`. These values are intentionally
not stored in this repository. Use a managed MySQL service with automated
backups and point-in-time recovery enabled. Keep the SQLite file as an offline
migration source/backup rather than dual-writing to it in production.

### Import existing SQLite data

First back up `scam_flagger.db`, provision an empty MySQL 8 database, and set
the five `MYSQL_*` connection variables in your shell. Then run the import once:

```powershell
$env:SPRING_PROFILES_ACTIVE = "mysql"
mvn -DskipTests package
java -jar target/scam-flagger-1.0.0.jar --app.migrate-sqlite-from="C:\path\to\scam_flagger.db"
```

The importer creates the MySQL tables, copies users, websites, reviews, IDs,
and timestamps in a single transaction, and leaves the SQLite source untouched.
It stops before importing if a username exceeds 80 characters, an email
exceeds 254 characters, or a URL exceeds 700 characters. It can be rerun safely
against the same target. After confirming the imported
record counts and application behavior, set the MySQL environment variables in
the deployment dashboard and deploy the app.
