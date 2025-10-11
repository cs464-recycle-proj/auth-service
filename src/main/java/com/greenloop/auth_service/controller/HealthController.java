package com.greenloop.auth_service.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/api/health")
public class HealthController {
    @GetMapping
    public ResponseEntity<Map<String, String>> checkHealth() {
        Map<String, String> response = Collections.singletonMap("status", "Auth Service is Up and Running!");
        return ResponseEntity.ok(response);
    }
}