# Scam Flagger — Design

## Purpose

Scam Flagger lets signed-in users assess a public website for risk indicators and
share community reviews. The application is a server-rendered Spring Boot web
app: browsers submit HTML forms, controllers coordinate application work, and
Thymeleaf renders the response pages.

## Design principles

- Keep the web app as one deployable Spring Boot application.
- Keep presentation, request coordination, analysis, and persistence in
  distinct components with simple interfaces.
- Use SQLite by default for local development and MySQL for the deployed
  `mysql` profile.
- Keep secrets in environment variables or the hosting provider's secret
  manager; do not commit credentials.
- Do not dual-write operational data to SQLite and MySQL. Use a one-time,
  repeatable SQLite-to-MySQL import and back up the production database through
  its managed provider.
- Treat risk scores as indicators rather than a definitive statement that a
  website is fraudulent.

## Application structure

| Area | Responsibility |
|---|---|
| `WebController` | Maps browser routes, checks session state, validates form data, and selects the Thymeleaf view. |
| `PageModelAdvice` | Adds the signed-in username and login state to page models and handles missing form parameters. |
| `PasswordService` | Hashes new passwords with BCrypt and verifies existing Werkzeug PBKDF2 hashes during account transition. |
| `RiskCalculator` | Normalizes website URLs, fetches public web pages, checks risk signals, and returns a score and explanations. |
| `DataStore` | Executes parameterized JDBC queries and writes for users, websites, and reviews. |
| Domain records | Carry user, website, review, and analysis data between components. |
| Thymeleaf templates | Render the home, login, registration, check, and results pages. |
| Database schema | Defines SQLite tables locally and corresponding MySQL tables in production. |
| `SqliteToMysqlMigration` | Imports existing SQLite rows to MySQL in a single target-database transaction when explicitly invoked. |

## User journeys

### Registration and login

1. The browser submits a registration form to `POST /register`.
2. `WebController` validates username, email, and password constraints.
3. `PasswordService` hashes the new password with BCrypt.
4. `DataStore` inserts the user. A username/email uniqueness conflict is
   reported as a duplicate registration; other database errors are surfaced.
5. On login, the controller loads the user by username and asks
   `PasswordService` to verify the password.
6. A successful login creates a session containing the user's ID and username.
   The existing Werkzeug PBKDF2 format is accepted so migrated accounts can
   continue to sign in.

### Website analysis

1. A signed-in user submits a URL to `POST /check`.
2. The controller normalizes the URL and checks for an existing record before
   performing external analysis.
3. On a cache miss, `RiskCalculator` resolves and checks the host, fetches the
   page with bounded timeouts and redirect handling, and examines page text,
   contact details, domain age, TLS certificate, testimonials, and design
   indicators.
4. The calculator returns a capped score and a list of triggered flags.
   Inaccessible websites receive the existing fixed penalty and an explanatory
   flag.
5. `DataStore` creates or updates the website record; the controller loads its
   community reviews and renders the result page.

### Community review

1. A signed-in user posts a website ID, 1–5 rating, and comment to
   `POST /review`.
2. The controller validates the values and verifies that the website exists.
3. `DataStore` inserts the review with a foreign-key reference to both the user
   and website.
4. The browser is redirected to that website's result page, where reviews are
   ordered newest first.

## Data model

- **User**: unique username and email, password hash, creation timestamp.
- **Website**: unique URL, risk score, flagged state, creation and last-check
  timestamps. A score of 70 or above is flagged.
- **Review**: user and website references, rating constrained to 1–5, optional
  comment, and creation timestamp.

The SQLite schema is in `src/main/resources/schema.sql`; the MySQL schema is in
`src/main/resources/schema-mysql.sql`. Keep the two definitions compatible when
the model changes.

## Persistence and deployment choices

- **Local default:** SQLite, using `scam_flagger.db` or the file specified by
  `DB_PATH`.
- **Production:** MySQL when `SPRING_PROFILES_ACTIVE=mysql` is set. Connection
  values are provided with `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_DATABASE`,
  `MYSQL_USER`, and `MYSQL_PASSWORD`.
- **Database backups:** Use the managed MySQL service's automated backups and
  point-in-time recovery. Retain a separate copy of the original SQLite file
  until migration and production data are verified.
- **Migration:** Run the explicit `app.migrate-sqlite-from` command described
  in `README.md`. The importer preserves IDs and timestamps and can be rerun
  against the same target.
- **Deployment topology:** One Dockerized Spring Boot web process connects to
  a separately provisioned MySQL service. The database is not bundled into the
  application container.

## Important boundaries and current limitations

- Website analysis performs outbound HTTP(S), DNS, WHOIS, and TLS checks. It is
  restricted to standard web ports and public hosts, with redirects validated
  before following them. These checks can still be slow or unavailable when
  external sites or WHOIS servers do not respond.
- Cached website checks return the stored result; they do not automatically
  refresh the analysis.
- Authentication is session-based and is enforced in the web controller.
  Before exposing the application to untrusted production traffic, add a
  dedicated Spring Security configuration, CSRF protection for state-changing
  forms, and rate limits for login, registration, and website analysis.
- Risk rules are heuristic. They can produce false positives and false
  negatives; show the score and its flags as decision support.
- The MySQL environment values are deployment placeholders. A real MySQL
  service, credentials, and backup policy must be configured by the operator.

## Change guidance

- Keep user-facing routes, session behavior, and messages aligned with the
  Thymeleaf pages.
- Add database changes to both schema files and preserve existing SQLite data
  during upgrades.
- Update this document and `architecture.md` when a component boundary,
  database flow, or deployment topology changes.
- Add tests for route workflows, database behavior, URL validation, and
  migration behavior when those areas change.
