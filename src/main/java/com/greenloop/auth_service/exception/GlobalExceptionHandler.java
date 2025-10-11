package com.greenloop.auth_service.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Handles the EmailAlreadyExistsException, mapping it to HTTP 409 Conflict.
     */
    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<Object> handleEmailAlreadyExists(EmailAlreadyExistsException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", HttpStatus.CONFLICT.value());
        body.put("error", "Conflict");
        body.put("message", ex.getMessage());
        return new ResponseEntity<>(body, HttpStatus.CONFLICT);
    }

    /**
     * Handles exceptions related to failed login attempts (AuthenticationException
     * from Spring Security
     * and our custom InvalidCredentialsException). Maps them to HTTP 401
     * Unauthorized.
     */
    @ExceptionHandler({ InvalidCredentialsException.class, AuthenticationException.class })
    public ResponseEntity<Object> handleAuthenticationExceptions(Exception ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", HttpStatus.UNAUTHORIZED.value());
        body.put("error", "Unauthorized");
        body.put("message", "Invalid email or password.");
        return new ResponseEntity<>(body, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Generic handler for all other unhandled Exceptions, mapping them to HTTP 500
     * Internal Server Error.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleGenericException(Exception ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        body.put("error", "Internal Server Error");
        body.put("message", "An unexpected error occurred.");
        return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}