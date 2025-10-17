package com.greenloop.auth_service.controller;

import com.greenloop.auth_service.dto.AuthResponse;
import com.greenloop.auth_service.dto.LoginRequest;
import com.greenloop.auth_service.dto.PasswordChangeRequest;
import com.greenloop.auth_service.dto.SignUpRequest;
import com.greenloop.auth_service.service.AuthService;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import java.util.Collections;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(
            @Valid @RequestBody SignUpRequest request,
            HttpServletResponse response) {
        return ResponseEntity.ok(authService.signup(request, response));
    }

    @PostMapping("/admin/signup")
    public ResponseEntity<AuthResponse> adminSignup(
            @Valid @RequestBody SignUpRequest request,
            HttpServletResponse response) {
        return ResponseEntity.ok(authService.adminSignup(request, response));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletResponse response) {
        return ResponseEntity.ok(authService.login(request, response));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletResponse response) {
        authService.logout(response);
        return ResponseEntity.ok(Collections.singletonMap("message", "Logout successful"));
    }

    @PutMapping("/password/reset")
    public ResponseEntity<Map<String, String>> resetPassword(
            @RequestHeader("X-User-ID") String userId,
            @Valid @RequestBody PasswordChangeRequest request) {

        authService.resetPassword(userId, request);

        return ResponseEntity.ok(Collections.singletonMap("message", "Password reset successful"));
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> checkHealth() {
        Map<String, String> response = Collections.singletonMap("status", "Auth Service is Up and Running!");
        return ResponseEntity.ok(response);
    }
}