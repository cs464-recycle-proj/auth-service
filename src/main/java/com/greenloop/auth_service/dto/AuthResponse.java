package com.greenloop.auth_service.dto;

import com.greenloop.auth_service.model.UserRole;
import lombok.*;

import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthResponse {
    private String token;
    private UUID userId;
    private String email;
    private UserRole role;
}