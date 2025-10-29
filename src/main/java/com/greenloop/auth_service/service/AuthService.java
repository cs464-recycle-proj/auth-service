package com.greenloop.auth_service.service;

import com.greenloop.auth_service.dto.AuthResponse;
import com.greenloop.auth_service.dto.LoginRequest;
import com.greenloop.auth_service.dto.PasswordChangeRequest;
import com.greenloop.auth_service.dto.SignUpRequest;
import com.greenloop.auth_service.exception.EmailAlreadyExistsException;
import com.greenloop.auth_service.exception.InvalidCredentialsException;
import com.greenloop.auth_service.exception.ResourceNotFoundException;
import com.greenloop.auth_service.exception.VerificationNotCompleteException;
import com.greenloop.auth_service.model.User;
import com.greenloop.auth_service.model.UserRole;
import com.greenloop.auth_service.repository.UserRepository;
import com.greenloop.auth_service.security.JwtService;
import com.greenloop.auth_service.util.CookieUtil;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import java.util.UUID;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Core authentication workflows: signup, admin signup, login, logout, and
 * password reset.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final VerificationService verificationService;
    private final CookieUtil cookieUtil;

    /**
     * Registers a new user and sets JWT in cookie.
     */
    @Transactional
    public AuthResponse signup(SignUpRequest request, HttpServletResponse response) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new EmailAlreadyExistsException("A user with this email address already exists.");
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(UserRole.USER)
                .build();

        User savedUser = userRepository.save(user);
        verificationService.createAndSendOtp(savedUser.getEmail());
        String jwtToken = jwtService.generateToken(savedUser);

        // Set token in HTTP-only cookie
        cookieUtil.addTokenCookie(response, jwtToken);

        return AuthResponse.builder()
                .userId(savedUser.getId())
                .email(savedUser.getEmail())
                .role(savedUser.getRole())
                .message("Signup successful. Verification OTP sent to email.")
                .build();
    }

    /**
     * Registers a new user with the ADMIN role. Only accessible by existing ADMIN
     * users.
     */
    @Transactional
    public AuthResponse adminSignup(SignUpRequest request, HttpServletResponse response) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new EmailAlreadyExistsException("A user with this email address already exists.");
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(UserRole.ADMIN)
                .isVerified(true)
                .build();

        User savedUser = userRepository.save(user);
        String jwtToken = jwtService.generateToken(savedUser);

        // Set token in HTTP-only cookie
        cookieUtil.addTokenCookie(response, jwtToken);

        return AuthResponse.builder()
                .userId(savedUser.getId())
                .email(savedUser.getEmail())
                .role(savedUser.getRole())
                .message("Admin account created successfully.")
                .build();
    }

    /**
     * Authenticates a user and sets JWT in cookie.
     */
    public AuthResponse login(LoginRequest request, HttpServletResponse response) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()));
        } catch (DisabledException e) {
            throw new VerificationNotCompleteException("Account not verified.");

        } catch (AuthenticationException e) {
            throw new InvalidCredentialsException("Invalid email or password.");
        }

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new InvalidCredentialsException("User not found after successful authentication."));

        String jwtToken = jwtService.generateToken(user);

        // Set token in HTTP-only cookie
        cookieUtil.addTokenCookie(response, jwtToken);

        return AuthResponse.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .role(user.getRole())
                .message("Login successful.")
                .build();
    }

    /**
     * Logs out user by clearing the auth cookie.
     */
    public void logout(HttpServletResponse response) {
        cookieUtil.deleteTokenCookie(response);
    }

    @Transactional
    public void resetPassword(String userId, PasswordChangeRequest request) {
        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new ResourceNotFoundException("User not found."));

        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new InvalidCredentialsException("Old password is incorrect.");
        }

        String encodedPassword = passwordEncoder.encode(request.getNewPassword());
        user.setPassword(encodedPassword);
        userRepository.save(user);
    }
}
