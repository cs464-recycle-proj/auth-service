// package com.greenloop.auth_service.test.integration;

// import com.fasterxml.jackson.databind.ObjectMapper;
// import com.greenloop.auth_service.dto.LoginRequest;
// import com.greenloop.auth_service.dto.SignUpRequest;
// import com.greenloop.auth_service.model.User;
// import com.greenloop.auth_service.model.UserRole;
// import com.greenloop.auth_service.repository.UserRepository;
// import com.greenloop.auth_service.repository.VerificationTokenRepository;
// import com.greenloop.auth_service.security.JwtService;
// import com.greenloop.auth_service.service.EmailService;
// import com.greenloop.auth_service.service.VerificationService;

// import org.junit.jupiter.api.BeforeEach;
// import org.junit.jupiter.api.Test;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
// import org.springframework.boot.test.context.SpringBootTest;
// import org.springframework.boot.test.mock.mockito.MockBean;
// import org.springframework.http.MediaType;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.test.context.ActiveProfiles;
// import org.springframework.test.web.servlet.MockMvc;

// import static org.hamcrest.Matchers.notNullValue;
// import static org.junit.jupiter.api.Assertions.*;
// import static org.mockito.ArgumentMatchers.anyString;
// import static org.mockito.Mockito.doNothing;
// import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// @SpringBootTest
// @AutoConfigureMockMvc
// @ActiveProfiles("test")
// class AuthControllerTest {

//         @Autowired
//         private MockMvc mockMvc;

//         @Autowired
//         private ObjectMapper objectMapper;

//         @Autowired
//         private UserRepository userRepository;

//         @Autowired
//         private PasswordEncoder passwordEncoder;

//         @Autowired
//         private JwtService jwtService;

//         @MockBean
//         private VerificationService verificationService;

//         @MockBean
//         private EmailService emailService;

//         @MockBean
//         private VerificationTokenRepository tokenRepository;

//         @BeforeEach
//         void setUp() {
//                 userRepository.deleteAll();
//                 doNothing().when(verificationService).createAndSendOtp(anyString());
//                 doNothing().when(emailService).sendOtpEmail(anyString(), anyString());
//         }

//         // -------------------- SIGNUP TESTS --------------------

//         @Test
//         void signup_WithValidRequest_ShouldReturnAuthResponse() throws Exception {
//                 SignUpRequest request = new SignUpRequest();
//                 request.setEmail("newuser@example.com");
//                 request.setPassword("password123");

//                 mockMvc.perform(post("/api/auth/signup")
//                                 .contentType(MediaType.APPLICATION_JSON)
//                                 .content(objectMapper.writeValueAsString(request)))
//                                 .andExpect(status().isOk())
//                                 .andExpect(jsonPath("$.token", notNullValue()))
//                                 .andExpect(jsonPath("$.userId", notNullValue()))
//                                 .andExpect(jsonPath("$.email").value("newuser@example.com"))
//                                 .andExpect(jsonPath("$.role").value("USER"));

//                 User saved = userRepository.findByEmail("newuser@example.com").orElse(null);
//                 assertNotNull(saved);
//                 assertTrue(passwordEncoder.matches("password123", saved.getPassword()));
//                 assertEquals(UserRole.USER, saved.getRole());
//         }

//         @Test
//         void signup_WithExistingEmail_ShouldReturnConflict() throws Exception {
//                 User existing = User.builder()
//                                 .email("existing@example.com")
//                                 .password(passwordEncoder.encode("password123"))
//                                 .role(UserRole.USER)
//                                 .isVerified(true)
//                                 .build();
//                 userRepository.save(existing);

//                 SignUpRequest request = new SignUpRequest();
//                 request.setEmail("existing@example.com");
//                 request.setPassword("newpassword");

//                 mockMvc.perform(post("/api/auth/signup")
//                                 .contentType(MediaType.APPLICATION_JSON)
//                                 .content(objectMapper.writeValueAsString(request)))
//                                 .andExpect(status().isConflict());
//         }

//         @Test
//         void signup_ShouldEncryptPassword() throws Exception {
//                 SignUpRequest request = new SignUpRequest();
//                 request.setEmail("encrypt@example.com");
//                 request.setPassword("plainpassword");

//                 mockMvc.perform(post("/api/auth/signup")
//                                 .contentType(MediaType.APPLICATION_JSON)
//                                 .content(objectMapper.writeValueAsString(request)))
//                                 .andExpect(status().isOk());

//                 User saved = userRepository.findByEmail("encrypt@example.com").orElse(null);
//                 assertNotNull(saved);
//                 assertNotEquals("plainpassword", saved.getPassword());
//                 assertTrue(passwordEncoder.matches("plainpassword", saved.getPassword()));
//         }

//         // -------------------- ADMIN SIGNUP TESTS --------------------

//         @Test
//         void adminSignup_WithValidRequest_ShouldCreateAdminUser() throws Exception {
//                 User admin = User.builder()
//                                 .email("admin@example.com")
//                                 .password(passwordEncoder.encode("adminpass"))
//                                 .role(UserRole.ADMIN)
//                                 .isVerified(true)
//                                 .build();
//                 userRepository.save(admin);
//                 String token = jwtService.generateToken(admin);

//                 SignUpRequest request = new SignUpRequest();
//                 request.setEmail("newadmin@example.com");
//                 request.setPassword("adminpassword");

//                 mockMvc.perform(post("/api/auth/admin/signup")
//                                 .header("Authorization", "Bearer " + token)
//                                 .contentType(MediaType.APPLICATION_JSON)
//                                 .content(objectMapper.writeValueAsString(request)))
//                                 .andExpect(status().isOk())
//                                 .andExpect(jsonPath("$.email").value("newadmin@example.com"))
//                                 .andExpect(jsonPath("$.role").value("ADMIN"));
//         }

//         @Test
//         void adminSignup_WithoutAuthentication_ShouldReturnForbidden() throws Exception {
//                 SignUpRequest request = new SignUpRequest();
//                 request.setEmail("newadmin@example.com");
//                 request.setPassword("adminpassword");

//                 mockMvc.perform(post("/api/auth/admin/signup")
//                                 .contentType(MediaType.APPLICATION_JSON)
//                                 .content(objectMapper.writeValueAsString(request)))
//                                 .andExpect(status().isForbidden());
//         }

//         // -------------------- LOGIN TESTS --------------------

//         @Test
//         void login_WithValidCredentials_ShouldReturnAuthResponse() throws Exception {
//                 User user = User.builder()
//                                 .email("user@example.com")
//                                 .password(passwordEncoder.encode("password123"))
//                                 .role(UserRole.USER)
//                                 .isVerified(true)
//                                 .build();
//                 userRepository.save(user);

//                 LoginRequest request = new LoginRequest();
//                 request.setEmail("user@example.com");
//                 request.setPassword("password123");

//                 mockMvc.perform(post("/api/auth/login")
//                                 .contentType(MediaType.APPLICATION_JSON)
//                                 .content(objectMapper.writeValueAsString(request)))
//                                 .andExpect(status().isOk())
//                                 .andExpect(jsonPath("$.email").value("user@example.com"))
//                                 .andExpect(jsonPath("$.role").value("USER"));
//         }

//         @Test
//         void login_WithInvalidPassword_ShouldReturnUnauthorized() throws Exception {
//                 User user = User.builder()
//                                 .email("user@example.com")
//                                 .password(passwordEncoder.encode("password123"))
//                                 .role(UserRole.USER)
//                                 .isVerified(true)
//                                 .build();
//                 userRepository.save(user);

//                 LoginRequest request = new LoginRequest();
//                 request.setEmail("user@example.com");
//                 request.setPassword("wrongpassword");

//                 mockMvc.perform(post("/api/auth/login")
//                                 .contentType(MediaType.APPLICATION_JSON)
//                                 .content(objectMapper.writeValueAsString(request)))
//                                 .andExpect(status().isUnauthorized());
//         }

//         @Test
//         void login_WithNonExistentEmail_ShouldReturnUnauthorized() throws Exception {
//                 LoginRequest request = new LoginRequest();
//                 request.setEmail("nonexistent@example.com");
//                 request.setPassword("password123");

//                 mockMvc.perform(post("/api/auth/login")
//                                 .contentType(MediaType.APPLICATION_JSON)
//                                 .content(objectMapper.writeValueAsString(request)))
//                                 .andExpect(status().isUnauthorized());
//         }
// }
