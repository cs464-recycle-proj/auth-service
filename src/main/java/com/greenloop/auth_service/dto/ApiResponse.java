package com.greenloop.auth_service.dto;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class ApiResponse {
    private LocalDateTime timestamp;
    private int status;
    private String error;
    private String message;
}