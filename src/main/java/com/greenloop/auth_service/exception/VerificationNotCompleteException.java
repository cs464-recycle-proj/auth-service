package com.greenloop.auth_service.exception;

public class VerificationNotCompleteException extends RuntimeException{
    public VerificationNotCompleteException(String message){
        super(message);
    }
}
