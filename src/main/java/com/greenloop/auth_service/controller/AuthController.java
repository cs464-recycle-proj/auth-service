package com.greenloop.auth_service.controller;

import com.greenloop.auth_service.dto.AuthResponse;
import com.greenloop.auth_service.dto.LoginRequest;
import com.greenloop.auth_service.dto.SignUpRequest;
import com.greenloop.auth_service.service.AuthService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(@RequestBody SignUpRequest request) {
        return ResponseEntity.ok(authService.signup(request));
    }

    @PostMapping("/admin/signup")
    public ResponseEntity<AuthResponse> adminSignup(@Valid @RequestBody SignUpRequest request) {
        return ResponseEntity.ok(authService.adminSignup(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }
}