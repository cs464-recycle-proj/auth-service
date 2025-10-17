# 🛡️ Auth Service

## 📘 Description

**auth-service** is a Spring Boot–based microservice that handles **user authentication and authorization**.
It provides secure user registration, login, and **role-based access control (USER / ADMIN)** using **JWT authentication**.

Key features include:

* **Email verification** via One-Time Passwords (OTPs) sent through Gmail SMTP
* **Password reset** and user verification tracking
* **Stateless JWT integration** for secure identity management across microservices
* **Cookie-based authentication**: JWT tokens are issued in cookies (`AUTH_TOKEN`) for session tracking and downstream gateway services

**Service Port:** `8081`  
**Database:** Supabase – Schema: `authentication`

---

## 🚀 Getting Started

### Run the Service Locally

```bash
./mvnw spring-boot:run
````

### Run Tests (Unit & Integration)

```bash
./mvnw test -Dspring.profiles.active=test
```

### Docker

This service is automatically set up when running the **Gateway Docker Compose**.

```bash
cd ../gateway
docker-compose up --build
```

This will start **both the Gateway and Auth Service** together.

---

## 📡 API Endpoints

| Endpoint                   | Method   | Description                                                                                   |
| -------------------------- | -------- | --------------------------------------------------------------------------------------------- |
| `/api/auth/signup`         | **POST** | Register a new user and trigger an OTP email for verification                                 |
| `/api/auth/login`          | **POST** | Login with email and password (only for verified users). Returns JWT in cookie (`AUTH_TOKEN`) |
| `/api/auth/admin/signup`   | **POST** | Register a new admin (secured endpoint)                                                       |
| `/api/auth/logout`         | **POST** | Logout the current user (clears JWT cookie)                                                   |
| `/api/auth/health`         | **GET**  | Health check for the authentication service                                                   |
| `/api/verify/send-otp`     | **POST** | Send or resend an OTP to the user’s registered email                                          |
| `/api/verify/check-otp`    | **POST** | Verify a user’s email using the OTP code                                                      |
| `/api/auth/password/reset` | **PUT**  | Reset a user’s password                                                                       |

---

## 🧩 Integration

* Issues **JWT tokens** stored in cookies (`AUTH_TOKEN`)
* Designed to integrate seamlessly with the **Gateway Service**, which:

  * Reads the cookie
  * Validates the JWT
  * Adds `X-User-ID` and `X-User-Role` headers for downstream services

This ensures other microservices don’t need to handle authentication directly.

---

## 🧱 Tech Stack

* **Java 21**
* **Spring Boot 3**
* **Spring Security + JWT**
* **Supabase (PostgreSQL)**
* **Docker-ready (via Gateway Docker Compose)**
* **Maven**

---

## ⚙️ CI/CD & Static Analysis

This service uses **GitHub Actions** for CI. The workflow includes:

* **SpotBugs**: analyzes potential bugs in the code.

  * **Fails the build only on High-priority bugs**
  * Generates an XML report (`target/spotbugsXml.xml`) for review
* **Checkstyle**: enforces code style rules using the Google Java Style.

  * **Does not fail the build** on violations
  * Generates an HTML report (`target/site/checkstyle.html`) if violations exist
* **Tests**: unit & integration tests are run in CI, and reports are archived

### Run Static Analysis Locally

#### SpotBugs

```bash
# Open the GUI to inspect bugs interactively
./mvnw spotbugs:gui

# Compile and check for bugs (will fail only on High-priority if configured)
./mvnw clean compile spotbugs:check
```

#### Checkstyle

```bash
# Check code style and generate report
./mvnw checkstyle:check
```

### CI Notes

* Workflow triggers on push or PR to `main` or `develop` branches affecting `auth-service/**`
* Artifacts such as SpotBugs and Checkstyle reports are uploaded for inspection even if the build does not fail
* This ensures developers can review code quality before merging
