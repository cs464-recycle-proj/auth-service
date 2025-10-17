package com.greenloop.auth_service.test.unit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.greenloop.auth_service.exception.OtpValidationException;
import com.greenloop.auth_service.exception.ResourceNotFoundException;
import com.greenloop.auth_service.exception.UserAlreadyVerifiedException;
import com.greenloop.auth_service.model.User;
import com.greenloop.auth_service.model.VerificationToken;
import com.greenloop.auth_service.repository.UserRepository;
import com.greenloop.auth_service.repository.VerificationTokenRepository;
import com.greenloop.auth_service.service.EmailService;
import com.greenloop.auth_service.service.VerificationService;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

@ExtendWith(MockitoExtension.class)
class VerificationServiceTest {

        @Mock
        private UserRepository userRepository;

        @Mock
        private VerificationTokenRepository tokenRepository;

        @Mock
        private EmailService emailService;

        @InjectMocks
        private VerificationService verificationService;

        private final String TEST_EMAIL = "test@example.com";
        private final String TEST_OTP = "123456";
        private final UUID TEST_USER_ID = UUID.randomUUID();
        private User unverifiedUser;
        private User verifiedUser;

        @BeforeEach
        void setUp() {
                ReflectionTestUtils.setField(verificationService, "otpExpirationMinutes", 5);

                unverifiedUser = User.builder()
                                .id(TEST_USER_ID)
                                .email(TEST_EMAIL)
                                .isVerified(false)
                                .build();

                verifiedUser = User.builder()
                                .id(TEST_USER_ID)
                                .email(TEST_EMAIL)
                                .isVerified(true)
                                .build();
        }

        @Test
        void createAndSendOtp_Success_NewToken() {
                when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(unverifiedUser));
                when(tokenRepository.findByUserId(TEST_USER_ID)).thenReturn(Optional.empty());

                verificationService.createAndSendOtp(TEST_EMAIL);

                verify(userRepository, times(1)).findByEmail(TEST_EMAIL);
                verify(tokenRepository, times(1)).save(argThat(token -> token.getUser().equals(unverifiedUser) &&
                                !token.isUsed()));
                verify(emailService, times(1)).sendOtpEmail(eq(TEST_EMAIL), anyString());
                verify(tokenRepository, never()).delete(any());
        }

        @Test
        void createAndSendOtp_Success_ExistingTokenDeleted() {
                VerificationToken existingToken = VerificationToken.builder()
                                .user(unverifiedUser)
                                .token("999999")
                                .expiryDate(Instant.now().minus(1, ChronoUnit.MINUTES))
                                .build();

                when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(unverifiedUser));
                when(tokenRepository.findByUserId(TEST_USER_ID)).thenReturn(Optional.of(existingToken));

                verificationService.createAndSendOtp(TEST_EMAIL);

                verify(tokenRepository, times(1)).delete(existingToken);
                verify(tokenRepository, times(1)).save(any(VerificationToken.class));
                verify(emailService, times(1)).sendOtpEmail(eq(TEST_EMAIL), anyString());
        }

        @Test
        void createAndSendOtp_Failure_UserNotFound() {
                when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.empty());

                assertThrows(ResourceNotFoundException.class,
                                () -> verificationService.createAndSendOtp(TEST_EMAIL));

                verify(tokenRepository, never()).save(any());
                verify(emailService, never()).sendOtpEmail(any(), any());
        }

        @Test
        void createAndSendOtp_Failure_UserAlreadyVerified() {
                when(userRepository.findByEmail(TEST_EMAIL)).thenReturn(Optional.of(verifiedUser));

                assertThrows(UserAlreadyVerifiedException.class,
                                () -> verificationService.createAndSendOtp(TEST_EMAIL));

                verify(tokenRepository, never()).save(any());
                verify(emailService, never()).sendOtpEmail(any(), any());
        }

        @Test
        void verifyOtp_Success() {
                VerificationToken validToken = VerificationToken.builder()
                                .user(unverifiedUser)
                                .token(TEST_OTP)
                                .isUsed(false)
                                .expiryDate(Instant.now().plus(5, ChronoUnit.MINUTES))
                                .build();

                when(tokenRepository.findByToken(TEST_OTP)).thenReturn(Optional.of(validToken));
                when(userRepository.save(any(User.class))).thenReturn(unverifiedUser);

                User resultUser = verificationService.verifyOtp(TEST_OTP, TEST_EMAIL);

                assertTrue(resultUser.isVerified());
                verify(tokenRepository, times(1)).save(argThat(token -> token.isUsed()));
                verify(userRepository, times(1)).save(argThat(user -> user.isVerified()));
        }

        @Test
        void verifyOtp_Failure_InvalidOtp() {
                when(tokenRepository.findByToken(TEST_OTP)).thenReturn(Optional.empty());

                assertThrows(OtpValidationException.class,
                                () -> verificationService.verifyOtp(TEST_OTP, TEST_EMAIL));

                verify(tokenRepository, never()).save(any());
                verify(userRepository, never()).save(any());
        }

        @Test
        void verifyOtp_Failure_EmailMismatch() {
                User otherUser = User.builder().email("other@example.com").isVerified(false).build();
                VerificationToken token = VerificationToken.builder()
                                .user(otherUser)
                                .token(TEST_OTP)
                                .isUsed(false)
                                .expiryDate(Instant.now().plus(5, ChronoUnit.MINUTES))
                                .build();

                when(tokenRepository.findByToken(TEST_OTP)).thenReturn(Optional.of(token));

                assertThrows(OtpValidationException.class,
                                () -> verificationService.verifyOtp(TEST_OTP, TEST_EMAIL));

                verify(userRepository, never()).save(any());
        }

        @Test
        void verifyOtp_Failure_ExpiredOtp() {
                VerificationToken expiredToken = VerificationToken.builder()
                                .user(unverifiedUser)
                                .token(TEST_OTP)
                                .isUsed(false)
                                .expiryDate(Instant.now().minus(1, ChronoUnit.MINUTES))
                                .build();

                when(tokenRepository.findByToken(TEST_OTP)).thenReturn(Optional.of(expiredToken));

                assertThrows(OtpValidationException.class,
                                () -> verificationService.verifyOtp(TEST_OTP, TEST_EMAIL));

                verify(tokenRepository, times(1)).delete(expiredToken);
                verify(userRepository, never()).save(any());
        }

        @Test
        void verifyOtp_Failure_AlreadyUsed() {
                VerificationToken usedToken = VerificationToken.builder()
                                .user(unverifiedUser)
                                .token(TEST_OTP)
                                .isUsed(true)
                                .expiryDate(Instant.now().plus(5, ChronoUnit.MINUTES))
                                .build();

                when(tokenRepository.findByToken(TEST_OTP)).thenReturn(Optional.of(usedToken));

                assertThrows(OtpValidationException.class,
                                () -> verificationService.verifyOtp(TEST_OTP, TEST_EMAIL));

                verify(tokenRepository, never()).save(any());
                verify(userRepository, never()).save(any());
        }
}
