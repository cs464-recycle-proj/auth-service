# 🛡️ Auth Service

## 📘 Description

**auth-service** is a Spring Boot–based microservice that handles **user authentication and authorization**.
It provides secure user registration, login, and **role-based access control (USER / ADMIN)** using **JWT authentication**.

Key features include:

* **Email verification** via One-Time Passwords (OTPs) sent through Gmail SMTP
* **Password reset** and user verification tracking
* **Stateless JWT integration** for secure identity management across microservices

**Service Port:** `8081`
**Database:** Supabase – Schema: `authentication`

---

## 🚀 Getting Started

### Run the Service

```bash
mvn spring-boot:run
```

### Run Tests (WIP)

```bash
mvn test -Dspring.profiles.active=test
```

---

## 📡 API Endpoints

| Endpoint                   | Method   | Description                                                   |
| -------------------------- | -------- | ------------------------------------------------------------- |
| `/api/auth/signup`         | **POST** | Register a new user and trigger an OTP email for verification |
| `/api/auth/login`          | **POST** | Login with email and password (only for verified users)       |
| `/api/auth/admin/signup`   | **POST** | Register a new admin (secured endpoint)                       |
| `/api/auth/logout`         | **POST** | Logout the current user                                       |
| `/api/auth/health`         | **GET**  | Health check for the authentication service                   |
| `/api/verify/send-otp`     | **POST** | Send or resend an OTP to the user’s registered email          |
| `/api/verify/check-otp`    | **POST** | Verify a user’s email using the OTP code                      |
| `/api/auth/password/reset` | **PUT**  | Reset a user’s password                                       |

---

## 🧩 Integration

This service issues **JWT tokens** that other microservices can validate to perform user authentication and authorization.
It’s designed to integrate seamlessly into a **microservices architecture** with centralized identity management.

---

## 🧱 Tech Stack

* **Java 17**
* **Spring Boot 3**
* **Spring Security + JWT**
* **Supabase (PostgreSQL)**
* **Docker-ready**
* **Maven**