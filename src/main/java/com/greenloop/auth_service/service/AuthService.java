package com.greenloop.auth_service.service;

import com.greenloop.auth_service.dto.AuthResponse;
import com.greenloop.auth_service.dto.LoginRequest;
import com.greenloop.auth_service.dto.SignUpRequest;
import com.greenloop.auth_service.exception.EmailAlreadyExistsException;
import com.greenloop.auth_service.exception.InvalidCredentialsException;
import com.greenloop.auth_service.model.User;
import com.greenloop.auth_service.model.UserRole;
import com.greenloop.auth_service.repository.UserRepository;
import com.greenloop.auth_service.security.JwtService;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    /**
     * Registers a new user.
     */
    public AuthResponse signup(SignUpRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new EmailAlreadyExistsException("A user with this email address already exists.");
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(UserRole.USER)
                .build();

        User savedUser = userRepository.save(user);
        String jwtToken = jwtService.generateToken(savedUser);

        return AuthResponse.builder()
                .token(jwtToken)
                .userId(savedUser.getId())
                .email(savedUser.getEmail())
                .role(savedUser.getRole())
                .build();
    }

    /**
     * Registers a new user with the ADMIN role. Only accessible by existing ADMIN
     * users.
     */
    public AuthResponse adminSignup(SignUpRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new EmailAlreadyExistsException("A user with this email address already exists.");
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(UserRole.ADMIN)
                .build();

        User savedUser = userRepository.save(user);
        String jwtToken = jwtService.generateToken(savedUser);

        return AuthResponse.builder()
                .token(jwtToken)
                .userId(savedUser.getId())
                .email(savedUser.getEmail())
                .role(savedUser.getRole())
                .build();
    }

    /**
     * Authenticates a user and returns a JWT.
     */
    public AuthResponse login(LoginRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()));
        } catch (AuthenticationException e) {
            throw new InvalidCredentialsException("Invalid email or password.");
        }

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new InvalidCredentialsException("User not found after successful authentication."));

        String jwtToken = jwtService.generateToken(user);

        return AuthResponse.builder()
                .token(jwtToken)
                .userId(user.getId())
                .email(user.getEmail())
                .role(user.getRole())
                .build();
    }
}