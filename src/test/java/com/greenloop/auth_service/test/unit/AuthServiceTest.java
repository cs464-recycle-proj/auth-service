package com.greenloop.auth_service.test.unit;

import com.greenloop.auth_service.dto.AuthResponse;
import com.greenloop.auth_service.dto.LoginRequest;
import com.greenloop.auth_service.dto.SignUpRequest;
import com.greenloop.auth_service.exception.EmailAlreadyExistsException;
import com.greenloop.auth_service.exception.InvalidCredentialsException;
import com.greenloop.auth_service.model.User;
import com.greenloop.auth_service.model.UserRole;
import com.greenloop.auth_service.repository.UserRepository;
import com.greenloop.auth_service.service.AuthService;
import com.greenloop.auth_service.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the AuthService, mocking all external dependencies
 * to test only the business logic.
 */
@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtService jwtService;
    @Mock
    private AuthenticationManager authenticationManager;

    @InjectMocks
    private AuthService authService;

    private SignUpRequest signUpRequest;
    private LoginRequest loginRequest;
    private User user;

    @BeforeEach
    void setUp() {
        signUpRequest = new SignUpRequest("test@example.com", "password123");
        loginRequest = new LoginRequest("test@example.com", "password123");
        user = User.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .password("encodedPassword")
                .role(UserRole.USER)
                .build();
    }

    // --- Signup Tests ---

    @Test
    void signup_SuccessfulRegistration() {
        when(userRepository.findByEmail(signUpRequest.getEmail())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(any(String.class))).thenReturn("encodedPassword");
        when(userRepository.save(any(User.class))).thenReturn(user);
        when(jwtService.generateToken(any(User.class))).thenReturn("fake-jwt-token");

        AuthResponse response = authService.signup(signUpRequest);

        assertNotNull(response);
        assertEquals("fake-jwt-token", response.getToken());
        assertEquals(UserRole.USER, response.getRole());
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    void signup_EmailAlreadyExists_ThrowsException() {
        when(userRepository.findByEmail(signUpRequest.getEmail())).thenReturn(Optional.of(user));
        assertThrows(EmailAlreadyExistsException.class, () -> authService.signup(signUpRequest));
        verify(userRepository, never()).save(any(User.class));
    }

    // --- Admin Signup Tests ---

    @Test
    void adminSignup_SuccessfulRegistration() {
        when(userRepository.findByEmail(signUpRequest.getEmail())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(any(String.class))).thenReturn("encodedPassword");
        User adminUser = User.builder()
                .role(UserRole.ADMIN)
                .build();
        when(userRepository.save(any(User.class))).thenReturn(adminUser);
        when(jwtService.generateToken(any(User.class))).thenReturn("fake-admin-jwt-token");

        AuthResponse response = authService.adminSignup(signUpRequest);
        assertNotNull(response);
        assertEquals("fake-admin-jwt-token", response.getToken());
        assertEquals(UserRole.ADMIN, response.getRole());
    }

    // --- Login Tests ---

    @Test
    void login_SuccessfulAuthentication() {
        when(userRepository.findByEmail(loginRequest.getEmail())).thenReturn(Optional.of(user));
        when(jwtService.generateToken(any(User.class))).thenReturn("fake-jwt-token");

        AuthResponse response = authService.login(loginRequest);

        assertNotNull(response);
        assertEquals("fake-jwt-token", response.getToken());
        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    void login_InvalidCredentials_ThrowsException() {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(mock(AuthenticationException.class));

        assertThrows(InvalidCredentialsException.class, () -> authService.login(loginRequest));
        verify(userRepository, never()).findByEmail(any(String.class));
    }
}
