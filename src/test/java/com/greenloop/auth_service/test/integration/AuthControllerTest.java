package com.greenloop.auth_service.test.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greenloop.auth_service.dto.LoginRequest;
import com.greenloop.auth_service.dto.SignUpRequest;
import com.greenloop.auth_service.model.User;
import com.greenloop.auth_service.model.UserRole;
import com.greenloop.auth_service.repository.UserRepository;
import com.greenloop.auth_service.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    void signup_WithValidRequest_ShouldReturnAuthResponse() throws Exception {
        SignUpRequest request = new SignUpRequest();
        request.setEmail("newuser@example.com");
        request.setPassword("password123");

        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token", notNullValue()))
                .andExpect(jsonPath("$.userId", notNullValue()))
                .andExpect(jsonPath("$.email").value("newuser@example.com"))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void signup_WithExistingEmail_ShouldReturnConflict() throws Exception {
        // Create existing user
        User existingUser = User.builder()
                .email("existing@example.com")
                .password(passwordEncoder.encode("password123"))
                .role(UserRole.USER)
                .build();
        userRepository.save(existingUser);

        SignUpRequest request = new SignUpRequest();
        request.setEmail("existing@example.com");
        request.setPassword("newpassword");

        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict());
    }

    @Test
    void adminSignup_WithValidRequest_ShouldCreateAdminUser() throws Exception {
        // Create an admin user for authentication
        User admin = User.builder()
                .email("admin@example.com")
                .password(passwordEncoder.encode("adminpass"))
                .role(UserRole.ADMIN)
                .build();
        userRepository.save(admin);
        String adminToken = jwtService.generateToken(admin);

        SignUpRequest request = new SignUpRequest();
        request.setEmail("newadmin@example.com");
        request.setPassword("adminpassword");

        mockMvc.perform(post("/api/auth/admin/signup")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token", notNullValue()))
                .andExpect(jsonPath("$.userId", notNullValue()))
                .andExpect(jsonPath("$.email").value("newadmin@example.com"))
                .andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    void adminSignup_WithExistingEmail_ShouldReturnConflict() throws Exception {
        // Create admin for auth
        User admin = User.builder()
                .email("admin@example.com")
                .password(passwordEncoder.encode("adminpass"))
                .role(UserRole.ADMIN)
                .build();
        userRepository.save(admin);
        String adminToken = jwtService.generateToken(admin);

        // Create existing user
        User existingUser = User.builder()
                .email("existing@example.com")
                .password(passwordEncoder.encode("password123"))
                .role(UserRole.USER)
                .build();
        userRepository.save(existingUser);

        SignUpRequest request = new SignUpRequest();
        request.setEmail("existing@example.com");
        request.setPassword("newpassword");

        mockMvc.perform(post("/api/auth/admin/signup")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict());
    }

    @Test
    void adminSignup_WithoutAuthentication_ShouldReturnUnauthorized() throws Exception {
        SignUpRequest request = new SignUpRequest();
        request.setEmail("newadmin@example.com");
        request.setPassword("adminpassword");

        mockMvc.perform(post("/api/auth/admin/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminSignup_WithRegularUserToken_ShouldReturnForbidden() throws Exception {
        // Create regular user
        User user = User.builder()
                .email("user@example.com")
                .password(passwordEncoder.encode("userpass"))
                .role(UserRole.USER)
                .build();
        userRepository.save(user);
        String userToken = jwtService.generateToken(user);

        SignUpRequest request = new SignUpRequest();
        request.setEmail("newadmin@example.com");
        request.setPassword("adminpassword");

        mockMvc.perform(post("/api/auth/admin/signup")
                .header("Authorization", "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    void login_WithValidCredentials_ShouldReturnAuthResponse() throws Exception {
        // Create user
        User user = User.builder()
                .email("user@example.com")
                .password(passwordEncoder.encode("password123"))
                .role(UserRole.USER)
                .build();
        userRepository.save(user);

        LoginRequest request = new LoginRequest();
        request.setEmail("user@example.com");
        request.setPassword("password123");

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token", notNullValue()))
                .andExpect(jsonPath("$.userId", notNullValue()))
                .andExpect(jsonPath("$.email").value("user@example.com"))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void login_WithInvalidPassword_ShouldReturnUnauthorized() throws Exception {
        // Create user
        User user = User.builder()
                .email("user@example.com")
                .password(passwordEncoder.encode("password123"))
                .role(UserRole.USER)
                .build();
        userRepository.save(user);

        LoginRequest request = new LoginRequest();
        request.setEmail("user@example.com");
        request.setPassword("wrongpassword");

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_WithNonExistentEmail_ShouldReturnUnauthorized() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setEmail("nonexistent@example.com");
        request.setPassword("password123");

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void signup_ShouldPersistUserInDatabase() throws Exception {
        SignUpRequest request = new SignUpRequest();
        request.setEmail("persist@example.com");
        request.setPassword("password123");

        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        // Verify user was persisted
        User savedUser = userRepository.findByEmail("persist@example.com").orElse(null);
        assert savedUser != null;
        assert savedUser.getEmail().equals("persist@example.com");
        assert savedUser.getRole() == UserRole.USER;
    }

    @Test
    void signup_ShouldEncryptPassword() throws Exception {
        SignUpRequest request = new SignUpRequest();
        request.setEmail("encrypt@example.com");
        request.setPassword("plainpassword");

        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());

        // Verify password is encrypted
        User savedUser = userRepository.findByEmail("encrypt@example.com").orElse(null);
        assert savedUser != null;
        assert !savedUser.getPassword().equals("plainpassword");
        assert passwordEncoder.matches("plainpassword", savedUser.getPassword());
    }
}