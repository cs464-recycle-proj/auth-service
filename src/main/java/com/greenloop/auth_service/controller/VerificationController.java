package com.greenloop.auth_service.controller;

import com.greenloop.auth_service.service.VerificationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Endpoints for sending and validating email verification OTP codes.
 */
@RestController
@RequestMapping("/api/verify")
@RequiredArgsConstructor
public class VerificationController {

    private final VerificationService verificationService;

    /**
     * Sends a one-time password (OTP) to the given email.
     */
    @PostMapping("/send-otp")
    public ResponseEntity<String> sendOtp(@RequestParam String email) {
        verificationService.createAndSendOtp(email);
        return ResponseEntity.ok("OTP successfully sent to " + email);
    }

    /**
     * Validates the OTP for the provided email.
     */
    @PostMapping("/check-otp")
    public ResponseEntity<String> checkOtp(@RequestParam String email, @RequestParam String otp) {
        verificationService.verifyOtp(otp, email);
        return ResponseEntity.ok("Account successfully verified! You can now log in.");
    }
}
