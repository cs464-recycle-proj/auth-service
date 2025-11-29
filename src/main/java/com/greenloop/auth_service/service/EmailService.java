package com.greenloop.auth_service.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.greenloop.auth_service.util.EmailTemplateUtil;

import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.HashMap;

@Service
@Slf4j
public class EmailService {

    private final WebClient webClient;
    
    @Value("${resend.api.key}")
    private String resendApiKey;
    
    @Value("${resend.from.email:onboarding@resend.dev}")
    private String fromEmail;

    public EmailService(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder
            .baseUrl("https://api.resend.com")
            .build();
    }

    /**
     * Sends an HTML OTP verification email to the user using Resend API.
     *
     * @param toEmail The recipient's email address.
     * @param otpCode The One-Time Password to send.
     */
    public void sendOtpEmail(String toEmail, String otpCode) {
        try {
            Map<String, Object> emailRequest = new HashMap<>();
            emailRequest.put("from", fromEmail);
            emailRequest.put("to", new String[]{toEmail});
            emailRequest.put("subject", "Your GreenLoop Account Verification Code (OTP)");
            emailRequest.put("html", EmailTemplateUtil.otpVerificationEmail(otpCode));

            webClient.post()
                .uri("/emails")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + resendApiKey)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(emailRequest)
                .retrieve()
                .bodyToMono(Map.class)
                .doOnSuccess(response -> {
                    log.info("OTP email sent successfully to: {} via Resend", toEmail);
                })
                .doOnError(error -> {
                    log.error("Failed to send OTP email to {}: {}", toEmail, error.getMessage());
                })
                .onErrorResume(e -> Mono.empty())
                .subscribe();

        } catch (Exception e) {
            log.error("Failed to send OTP email to {}: {}", toEmail, e.getMessage());
        }
    }
}
