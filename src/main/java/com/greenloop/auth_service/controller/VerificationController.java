package com.greenloop.auth_service.controller;

import com.greenloop.auth_service.service.VerificationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/verify")
@RequiredArgsConstructor
public class VerificationController {

    private final VerificationService verificationService;

    /**
     * Endpoint to resend the OTP to a user's email.
     * @param email The email address of the user.
     */
    @PostMapping("/send-otp")
    public ResponseEntity<String> sendOtp(@RequestParam String email) {
        try {
            // Note: This service method will also handle resource not found and already verified exceptions.
            verificationService.createAndSendOtp(email);
            return ResponseEntity.ok("OTP successfully sent to " + email);
        } catch (Exception e) {
            // Using a simple message here. In a real application, you would use a global
            // exception handler to map these exceptions to correct HTTP status codes (e.g., 404, 400).
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    /**
     * Endpoint for the user to submit the OTP for verification.
     * @param email The user's email address.
     * @param otp The OTP code submitted by the user.
     */
    @PostMapping("/check-otp")
    public ResponseEntity<String> checkOtp(@RequestParam String email, @RequestParam String otp) {
        try {
            verificationService.verifyOtp(otp, email);
            return ResponseEntity.ok("Account successfully verified! You can now log in.");
        } catch (IllegalArgumentException e) {
            // Handles invalid, expired, or used OTPs
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            // Handles other issues like resource not found
            return ResponseEntity.internalServerError().body("Verification failed: " + e.getMessage());
        }
    }
}
