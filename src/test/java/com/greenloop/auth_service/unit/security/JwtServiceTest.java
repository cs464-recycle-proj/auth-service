package com.greenloop.auth_service.unit.security;

import com.greenloop.auth_service.model.User;
import com.greenloop.auth_service.model.UserRole;
import com.greenloop.auth_service.security.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private JwtService jwtService;
    private String base64Key;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        // 32-byte (256-bit) key
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++)
            key[i] = (byte) (i + 1);
        base64Key = Base64.getEncoder().encodeToString(key);

        ReflectionTestUtils.setField(jwtService, "jwtSecret", base64Key);
        ReflectionTestUtils.setField(jwtService, "issuer", "auth-service");
        ReflectionTestUtils.setField(jwtService, "jwtExpirationMs", Duration.ofMinutes(5).toMillis());
    }

    private User newUser() {
        return User.builder()
                .id(UUID.randomUUID())
                .email("user@example.com")
                .role(UserRole.USER)
                .build();
    }

    @Test
    void generateToken_ThenExtractClaims_Succeeds() {
        User user = newUser();
        String token = jwtService.generateToken(user);

        Claims claims = jwtService.extractAllClaims(token);
        assertEquals("auth-service", claims.getIssuer());
        assertEquals(user.getId().toString(), claims.getSubject());
        assertEquals(user.getEmail(), claims.get("email", String.class));
        assertEquals("USER", claims.get("role", String.class));

        assertEquals(user.getEmail(), jwtService.extractUsername(token));
        assertEquals(user.getId(), jwtService.extractUserId(token));
        assertEquals("USER", jwtService.extractRole(token));
        assertFalse(jwtService.isTokenExpired(token));
        assertTrue(jwtService.isTokenValid(token));
    }

    @Test
    void expiredToken_ShouldThrowExpiredJwtException() throws InterruptedException {
        User user = newUser();
        // Short expiration
        ReflectionTestUtils.setField(jwtService, "jwtExpirationMs", 1L);
        String token = jwtService.generateToken(user);

        // Ensure expiration
        Thread.sleep(5);

        assertThrows(ExpiredJwtException.class, () -> jwtService.extractAllClaims(token));
        assertTrue(jwtService.isTokenExpired(token));
        assertFalse(jwtService.isTokenValid(token));
    }

    @Test
    void invalidSignature_ShouldThrowJwtException() {
        // Create a token with a different key via a second service instance
        JwtService other = new JwtService();
        byte[] otherKey = new byte[32];
        for (int i = 0; i < otherKey.length; i++)
            otherKey[i] = (byte) (i + 11);
        String otherBase64 = Base64.getEncoder().encodeToString(otherKey);
        ReflectionTestUtils.setField(other, "jwtSecret", otherBase64);
        ReflectionTestUtils.setField(other, "issuer", "auth-service");
        ReflectionTestUtils.setField(other, "jwtExpirationMs", 60_000L);

        String token = other.generateToken(newUser());

        assertThrows(JwtException.class, () -> jwtService.extractAllClaims(token));
        assertFalse(jwtService.isTokenValid(token));
    }
}
