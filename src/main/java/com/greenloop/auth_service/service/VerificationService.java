package com.greenloop.auth_service.service;

import com.greenloop.auth_service.exception.ResourceNotFoundException;
import com.greenloop.auth_service.exception.UserAlreadyVerifiedException;
import com.greenloop.auth_service.model.User;
import com.greenloop.auth_service.model.VerificationToken;
import com.greenloop.auth_service.repository.UserRepository;
import com.greenloop.auth_service.repository.VerificationTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.Random;

@Service
@RequiredArgsConstructor
@Slf4j
public class VerificationService {

    private final UserRepository userRepository;
    private final VerificationTokenRepository tokenRepository;
    private final EmailService emailService;

    // Inject the OTP expiration time from configuration
    @Value("${otp.expiration-minutes:5}") // Default to 5 minutes
    private int otpExpirationMinutes;

    /**
     * Generates a new OTP, saves it to the database, and sends it via email.
     * If an existing unverified token exists for the user, it is replaced.
     * 
     * @param email The email of the user to verify.
     */
    @Transactional
    public void createAndSendOtp(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));

        if (user.isVerified()) {
            throw new UserAlreadyVerifiedException(email);
        }

        String otpCode = String.format("%06d", new Random().nextInt(999999));
        Instant expirationTime = Instant.now().plus(otpExpirationMinutes, ChronoUnit.MINUTES);
        Optional<VerificationToken> existingToken = tokenRepository.findByUserId(user.getId());
        existingToken.ifPresent(tokenRepository::delete);

        VerificationToken token = tokenRepository.findByUserId(user.getId())
                .orElse(VerificationToken.builder()
                        .user(user)
                        .build());

        token.setToken(otpCode);
        token.setExpiryDate(expirationTime);
        token.setUsed(false);

        tokenRepository.save(token);
        log.info("New OTP generated for user {}. Expires at: {}", email, expirationTime);
        emailService.sendOtpEmail(user.getEmail(), otpCode);
    }

    /**
     * Validates the submitted OTP code.
     * 
     * @param otpCode The code submitted by the user.
     * @param email   The user's email (for sanity check/lookup efficiency).
     * @return The verified User object.
     * @throws IllegalArgumentException if the OTP is invalid, expired, or already
     *                                  used.
     */
    @Transactional
    public User verifyOtp(String otpCode, String email) {
        VerificationToken token = tokenRepository.findByToken(otpCode)
                .orElseThrow(() -> new IllegalArgumentException("Invalid OTP code."));

        if (!token.getUser().getEmail().equalsIgnoreCase(email)) {
            throw new IllegalArgumentException("OTP code does not match the provided user email.");
        }

        if (token.isExpired()) {
            tokenRepository.delete(token);
            throw new IllegalArgumentException("OTP code has expired. Please request a new one.");
        }

        if (token.isUsed()) {
            throw new IllegalArgumentException("OTP code has already been used.");
        }

        User user = token.getUser();
        if (user.isVerified()) {
            // This is a race condition or an unexpected scenario
            log.warn("Attempt to verify an already verified user: {}", user.getEmail());
            tokenRepository.delete(token); // Clean up the token
            return user;
        }

        // 5. Success: Mark token as used and verify the user
        token.setUsed(true);
        tokenRepository.save(token); // Update token status

        user.setVerified(true);
        userRepository.save(user); // Update user status
        log.info("User {} successfully verified.", user.getEmail());

        return user;
    }
}
