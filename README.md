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

| Endpoint                 | Method | Description                    |
| ------------------------ | ------ | ------------------------------ |
| `/api/auth/signup`       | POST   | Register a new user            |
| `/api/auth/login`        | POST   | Login with email and password  |
| `/api/auth/admin/signup` | POST   | Register a new admin (secured) |
| `/api/health`            | GET    | Health check (service status)  |
