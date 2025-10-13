package com.greenloop.auth_service.exception;

public class UserAlreadyVerifiedException extends RuntimeException {
    public UserAlreadyVerifiedException(String email) {
        super("User with email: " + email + " is already verified.");
    }
}
