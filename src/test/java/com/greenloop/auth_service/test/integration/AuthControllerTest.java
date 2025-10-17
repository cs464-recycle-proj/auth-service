package com.greenloop.auth_service.test.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greenloop.auth_service.dto.LoginRequest;
import com.greenloop.auth_service.dto.SignUpRequest;
import com.greenloop.auth_service.model.User;
import com.greenloop.auth_service.model.UserRole;
import com.greenloop.auth_service.repository.UserRepository;
import com.greenloop.auth_service.service.VerificationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockCookie;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerTest {

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private ObjectMapper objectMapper;

        @Autowired
        private UserRepository userRepository;

        @Autowired
        private PasswordEncoder passwordEncoder;

        @MockBean
        private VerificationService verificationService;

        @BeforeEach
        void setUp() {
                userRepository.deleteAll();
                doNothing().when(verificationService).createAndSendOtp(anyString());
        }

        // -------------------- SIGNUP TESTS --------------------

        @Test
        void signup_WithValidRequest_ShouldReturnAuthResponse() throws Exception {
                SignUpRequest request = new SignUpRequest();
                request.setEmail("newuser@example.com");
                request.setPassword("password123");

                mockMvc.perform(post("/api/auth/signup")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.userId", notNullValue()))
                                .andExpect(jsonPath("$.email").value("newuser@example.com"))
                                .andExpect(jsonPath("$.role").value("USER"))
                                .andExpect(cookie().exists("AUTH_TOKEN"))
                                .andExpect(cookie().httpOnly("AUTH_TOKEN", true))
                                .andExpect(cookie().path("AUTH_TOKEN", "/"));

                User saved = userRepository.findByEmail("newuser@example.com").orElse(null);
                assertNotNull(saved);
                assertTrue(passwordEncoder.matches("password123", saved.getPassword()));
                assertEquals(UserRole.USER, saved.getRole());
        }

        @Test
        void signup_WithExistingEmail_ShouldReturnConflict() throws Exception {
                // Create existing user
                User existingUser = User.builder()
                                .email("existing@example.com")
                                .password(passwordEncoder.encode("password"))
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

        // -------------------- ADMIN SIGNUP TESTS --------------------

        @Test
        void adminSignup_WithValidRequest_ShouldCreateAdminUser() throws Exception {
                // Create an admin user first
                User admin = User.builder()
                                .email("admin@example.com")
                                .password(passwordEncoder.encode("adminpass"))
                                .role(UserRole.ADMIN)
                                .isVerified(true)
                                .build();
                userRepository.save(admin);

                // Login as admin to get cookie
                LoginRequest loginRequest = new LoginRequest();
                loginRequest.setEmail("admin@example.com");
                loginRequest.setPassword("adminpass");

                String loginCookie = mockMvc.perform(post("/api/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(loginRequest)))
                                .andExpect(status().isOk())
                                .andExpect(cookie().exists("AUTH_TOKEN"))
                                .andReturn().getResponse().getCookie("AUTH_TOKEN").getValue();

                SignUpRequest request = new SignUpRequest();
                request.setEmail("newadmin@example.com");
                request.setPassword("adminpassword");

                mockMvc.perform(post("/api/auth/admin/signup")
                                .cookie(new MockCookie("AUTH_TOKEN", loginCookie))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.email").value("newadmin@example.com"))
                                .andExpect(jsonPath("$.role").value("ADMIN"))
                                .andExpect(cookie().exists("AUTH_TOKEN"))
                                .andExpect(cookie().httpOnly("AUTH_TOKEN", true));
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

        // -------------------- LOGIN TESTS --------------------

        @Test
        void login_WithValidCredentials_ShouldReturnAuthResponse() throws Exception {
                User user = User.builder()
                                .email("user@example.com")
                                .password(passwordEncoder.encode("password123"))
                                .role(UserRole.USER)
                                .isVerified(true)
                                .build();
                userRepository.save(user);

                LoginRequest request = new LoginRequest();
                request.setEmail("user@example.com");
                request.setPassword("password123");

                mockMvc.perform(post("/api/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.email").value("user@example.com"))
                                .andExpect(jsonPath("$.role").value("USER"))
                                .andExpect(cookie().exists("AUTH_TOKEN"))
                                .andExpect(cookie().httpOnly("AUTH_TOKEN", true))
                                .andExpect(cookie().path("AUTH_TOKEN", "/"));
        }

        @Test
        void login_WithInvalidPassword_ShouldReturnUnauthorized() throws Exception {
                User user = User.builder()
                                .email("user@example.com")
                                .password(passwordEncoder.encode("password123"))
                                .role(UserRole.USER)
                                .isVerified(true)
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

        // -------------------- LOGOUT TESTS --------------------

        @Test
        void logout_ShouldClearAuthCookie() throws Exception {
                mockMvc.perform(post("/api/auth/logout"))
                                .andExpect(status().isOk())
                                .andExpect(cookie().value("AUTH_TOKEN", ""))
                                .andExpect(cookie().maxAge("AUTH_TOKEN", 0));
        }
}