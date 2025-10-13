# auth-service

## Description
`auth-service` is a Spring Boot authentication service for user registration, login, and role-based access (USER/ADMIN).  
Runs on **port 8081**.

---

## Running

Start the service:

```bash
mvn spring-boot:run
````

Run tests with the `test` profile:

```bash
mvn test -Dspring.profiles.active=test
```

---

## Endpoints

## API Endpoints

| Endpoint                     | Method | Description |
| ----------------------------- | ------- | ------------ |
| `/api/auth/signup`            | POST    | Register a new user and trigger an OTP email for verification |
| `/api/auth/login`             | POST    | Login with email and password (only for verified users) |
| `/api/auth/admin/signup`      | POST    | Register a new admin (secured endpoint) |
| `/api/auth/logout`            | POST    | Logout the current user |
| `/api/auth/health`            | GET     | Health check for the authentication service |
| `/api/verify/send-otp`        | POST    | Send or resend an OTP to the user’s registered email for verification |
| `/api/verify/check-otp`       | POST    | Verify a user’s email address using the OTP code |
| `/api/auth/password/reset`    | PUT     | Reset a user’s password |

