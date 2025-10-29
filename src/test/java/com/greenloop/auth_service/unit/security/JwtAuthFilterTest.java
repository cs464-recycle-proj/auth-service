package com.greenloop.auth_service.unit.security;

import com.greenloop.auth_service.security.JwtAuthFilter;
import com.greenloop.auth_service.security.JwtService;
import com.greenloop.auth_service.util.CookieUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthFilterTest {

    @Mock
    private JwtService jwtService;
    @Mock
    private UserDetailsService userDetailsService;
    @Mock
    private CookieUtil cookieUtil;
    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private JwtAuthFilter filter;

    private UserDetails userDetails;

    @BeforeEach
    void setUp() {
        userDetails = new User("user@example.com", "pass", Collections.emptyList());
    }

    @Test
    void noToken_ShouldPassThrough() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        when(cookieUtil.getTokenFromCookie(any())).thenReturn(Optional.empty());

        filter.doFilter(request, response, filterChain);

        verify(filterChain, times(1)).doFilter(any(), any());
    }

    @Test
    void tokenInCookie_Valid_ShouldAuthenticate() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String token = "valid.jwt";

        when(cookieUtil.getTokenFromCookie(any())).thenReturn(Optional.of(token));
        when(jwtService.extractUsername(token)).thenReturn("user@example.com");
        when(userDetailsService.loadUserByUsername("user@example.com")).thenReturn(userDetails);
        when(jwtService.isTokenValid(token, userDetails)).thenReturn(true);

        filter.doFilter(request, response, filterChain);

        verify(filterChain, times(1)).doFilter(any(), any());
    }

    @Test
    void invalidToken_ShouldReturn401() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String token = "bad.jwt";

        when(cookieUtil.getTokenFromCookie(any())).thenReturn(Optional.of(token));
        when(jwtService.extractUsername(token)).thenThrow(new JwtException("Invalid"));

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertTrue(response.getContentAsString().contains("Invalid token"));
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void expiredToken_ShouldClearCookieAndReturn401() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String token = "expired.jwt";

        when(cookieUtil.getTokenFromCookie(any())).thenReturn(Optional.of(token));
        when(jwtService.extractUsername(token)).thenThrow(new ExpiredJwtException(null, null, "Expired"));

        filter.doFilter(request, response, filterChain);

        assertEquals(401, response.getStatus());
        assertTrue(response.getContentAsString().contains("Token expired"));
        verify(cookieUtil, times(1)).deleteTokenCookie(any());
        verify(filterChain, never()).doFilter(any(), any());
    }
}
