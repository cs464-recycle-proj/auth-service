package com.greenloop.auth_service.service;

import com.greenloop.auth_service.exception.OtpValidationException;
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

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class VerificationService {

    private final UserRepository userRepository;
    private final VerificationTokenRepository tokenRepository;
    private final EmailService emailService;

    @Value("${otp.expiration-minutes}")
    private int otpExpirationMinutes;

    private static final SecureRandom secureRandom = new SecureRandom();

    @Transactional
    public void createAndSendOtp(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));

        if (user.isVerified()) {
            throw new UserAlreadyVerifiedException(email);
        }

        String otpCode = String.format("%06d", secureRandom.nextInt(1_000_000));
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

    @Transactional
    public User verifyOtp(String otpCode, String email) {
        VerificationToken token = tokenRepository.findByToken(otpCode)
                .orElseThrow(() -> new OtpValidationException("Invalid OTP code."));

        if (!token.getUser().getEmail().equalsIgnoreCase(email)) {
            throw new OtpValidationException("OTP code does not match the provided user email.");
        }

        if (token.isExpired()) {
            tokenRepository.delete(token);
            throw new OtpValidationException("OTP code has expired. Please request a new one.");
        }

        if (token.isUsed()) {
            throw new OtpValidationException("OTP code has already been used.");
        }

        User user = token.getUser();

        token.setUsed(true);
        tokenRepository.save(token);

        user.setVerified(true);
        userRepository.save(user);
        log.info("User {} successfully verified.", user.getEmail());

        return user;
    }
}
