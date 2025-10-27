package com.greenloop.auth_service.integration;

import com.greenloop.auth_service.service.VerificationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class VerificationControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private VerificationService verificationService;

    private final String TEST_EMAIL = "test@example.com";
    private final String TEST_OTP = "123456";

    // --- SUCCESS PATH TESTS ---

    @Test
    void sendOtp_ShouldReturnOk() throws Exception {
        doNothing().when(verificationService).createAndSendOtp(TEST_EMAIL);

        mockMvc.perform(post("/api/verify/send-otp")
                .param("email", TEST_EMAIL)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string("OTP successfully sent to " + TEST_EMAIL));

        verify(verificationService, times(1)).createAndSendOtp(TEST_EMAIL);
    }

    @Test
    void checkOtp_ShouldReturnOk() throws Exception {
        when(verificationService.verifyOtp(anyString(), anyString())).thenReturn(null);

        mockMvc.perform(post("/api/verify/check-otp")
                .param("email", TEST_EMAIL)
                .param("otp", TEST_OTP)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string("Account successfully verified! You can now log in."));

        verify(verificationService, times(1)).verifyOtp(TEST_OTP, TEST_EMAIL);
    }
}
