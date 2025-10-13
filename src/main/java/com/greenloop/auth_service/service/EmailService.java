package com.greenloop.auth_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    // Note: You should configure 'spring.mail.username' in application.properties
    // If you don't use a dedicated property for the sender email, you can use the configured username.
    private final String senderEmail = "your-support-email@greenloop.com"; 

    /**
     * Sends a simple OTP verification email to the user.
     * @param toEmail The recipient's email address.
     * @param otpCode The One-Time Password to send.
     */
    public void sendOtpEmail(String toEmail, String otpCode) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(senderEmail);
            message.setTo(toEmail);
            message.setSubject("Your GreenLoop Account Verification Code (OTP)");
            
            String body = String.format(
                "Hello,\n\n" +
                "Thank you for registering with GreenLoop. Please use the following One-Time Password (OTP) to verify your account:\n\n" +
                "OTP: %s\n\n" +
                "This code is valid for 5 minutes and can only be used once.\n\n" +
                "If you did not request this code, please ignore this email.\n\n" +
                "Regards,\n" +
                "The GreenLoop Team", otpCode
            );
            
            message.setText(body);
            mailSender.send(message);
            log.info("OTP email sent successfully to: {}", toEmail);

        } catch (Exception e) {
            log.error("Failed to send OTP email to {}: {}", toEmail, e.getMessage());
            // In a real application, you might throw a custom exception here
            // to inform the client that the email failed.
        }
    }
}
