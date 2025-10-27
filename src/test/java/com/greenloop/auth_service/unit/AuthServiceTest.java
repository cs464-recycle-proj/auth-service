package com.greenloop.auth_service.unit;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.junit.jupiter.api.Assertions.*;

import com.greenloop.auth_service.dto.AuthResponse;
import com.greenloop.auth_service.dto.LoginRequest;
import com.greenloop.auth_service.dto.PasswordChangeRequest;
import com.greenloop.auth_service.dto.SignUpRequest;
import com.greenloop.auth_service.exception.EmailAlreadyExistsException;
import com.greenloop.auth_service.exception.InvalidCredentialsException;
import com.greenloop.auth_service.exception.ResourceNotFoundException;
import com.greenloop.auth_service.model.User;
import com.greenloop.auth_service.model.UserRole;
import com.greenloop.auth_service.repository.UserRepository;
import com.greenloop.auth_service.service.AuthService;
import com.greenloop.auth_service.service.VerificationService;
import com.greenloop.auth_service.security.JwtService;
import com.greenloop.auth_service.util.CookieUtil;

import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.UUID;

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
    @Mock
    private VerificationService verificationService;
    @Mock
    private CookieUtil cookieUtil;
    @Mock
    private HttpServletResponse response;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        authService = new AuthService(userRepository, passwordEncoder, jwtService,
                authenticationManager, verificationService, cookieUtil);
    }

    @Test
    void signup_WithNewEmail_ShouldCreateUser() {
        // Arrange
        SignUpRequest request = new SignUpRequest();
        request.setEmail("test@example.com");
        request.setPassword("password123");

        when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(any())).thenReturn("encodedPassword");
        when(userRepository.save(any())).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(UUID.randomUUID());
            return user;
        });
        when(jwtService.generateToken(any(User.class))).thenReturn("jwt-token");

        // Act
        AuthResponse response = authService.signup(request, this.response);

        // Assert
        assertNotNull(response);
        assertEquals(request.getEmail(), response.getEmail());
        assertEquals(UserRole.USER, response.getRole());
        verify(verificationService).createAndSendOtp(request.getEmail());
        verify(cookieUtil).addTokenCookie(any(), any());
    }

    @Test
    void signup_WithExistingEmail_ShouldThrowException() {
        // Arrange
        SignUpRequest request = new SignUpRequest();
        request.setEmail("existing@example.com");
        request.setPassword("password123");

        when(userRepository.findByEmail(request.getEmail()))
                .thenReturn(Optional.of(new User()));

        // Act & Assert
        assertThrows(EmailAlreadyExistsException.class,
                () -> authService.signup(request, response));
    }

    @Test
    void login_WithValidCredentials_ShouldSucceed() {
        // Arrange
        LoginRequest request = new LoginRequest();
        request.setEmail("test@example.com");
        request.setPassword("password123");

        User user = User.builder()
                .id(UUID.randomUUID())
                .email(request.getEmail())
                .role(UserRole.USER)
                .build();

        when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(user));
        when(jwtService.generateToken(user)).thenReturn("jwt-token");

        // Act
        AuthResponse response = authService.login(request, this.response);

        // Assert
        assertNotNull(response);
        assertEquals(user.getEmail(), response.getEmail());
        assertEquals(user.getRole(), response.getRole());
        verify(authenticationManager).authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        verify(cookieUtil).addTokenCookie(any(), any());
    }

    @Test
    void login_WithInvalidCredentials_ShouldThrowException() {
        // Arrange
        LoginRequest request = new LoginRequest();
        request.setEmail("test@example.com");
        request.setPassword("wrongpassword");

        when(authenticationManager.authenticate(any()))
                .thenThrow(new InvalidCredentialsException("Invalid credentials"));

        // Act & Assert
        assertThrows(InvalidCredentialsException.class,
                () -> authService.login(request, response));
    }

    @Test
    void resetPassword_WithValidCredentials_ShouldSucceed() {
        // Arrange
        UUID userId = UUID.randomUUID();
        String oldPassword = "oldPassword";
        String newPassword = "newPassword";

        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword(oldPassword);
        request.setNewPassword(newPassword);

        User user = User.builder()
                .id(userId)
                .email("test@example.com")
                .password("encodedOldPassword")
                .build();

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(oldPassword, user.getPassword())).thenReturn(true);
        when(passwordEncoder.encode(newPassword)).thenReturn("encodedNewPassword");

        // Act
        authService.resetPassword(userId.toString(), request);

        // Assert
        verify(userRepository).save(user);
        assertEquals("encodedNewPassword", user.getPassword());
    }

    @Test
    void resetPassword_WithInvalidOldPassword_ShouldThrowException() {
        // Arrange
        UUID userId = UUID.randomUUID();
        String oldPassword = "wrongPassword";
        String newPassword = "newPassword";

        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword(oldPassword);
        request.setNewPassword(newPassword);

        User user = User.builder()
                .id(userId)
                .email("test@example.com")
                .password("encodedOldPassword")
                .build();

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(oldPassword, user.getPassword())).thenReturn(false);

        // Act & Assert
        assertThrows(InvalidCredentialsException.class,
                () -> authService.resetPassword(userId.toString(), request));
    }

    @Test
    void resetPassword_WithNonExistentUser_ShouldThrowException() {
        // Arrange
        UUID userId = UUID.randomUUID();
        PasswordChangeRequest request = new PasswordChangeRequest();
        request.setOldPassword("oldPassword");
        request.setNewPassword("newPassword");

        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(ResourceNotFoundException.class,
                () -> authService.resetPassword(userId.toString(), request));
    }

    @Test
    void logout_ShouldClearAuthCookie() {
        // Act
        authService.logout(response);

        // Assert
        verify(cookieUtil).deleteTokenCookie(response);
    }
}