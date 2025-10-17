package com.greenloop.auth_service.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

@Component
public class CookieUtil {

    @Value("${jwt.cookie.name:AUTH_TOKEN}")
    private String cookieName;

    @Value("${jwt.cookie.max-age:86400}") // Default 24 hours
    private int cookieMaxAge;

    @Value("${jwt.cookie.secure:false}") // Set to true in production with HTTPS
    private boolean secure;

    @Value("${jwt.cookie.same-site:Lax}") // Lax, Strict, or None
    private String sameSite;

    @Value("${jwt.cookie.domain:}")
    private String domain;

    @Value("${jwt.cookie.path:/}")
    private String path;

    /**
     * Add JWT token as HTTP-only cookie to response
     */
    public void addTokenCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie(cookieName, token);
        cookie.setHttpOnly(true); // Prevents JavaScript access (XSS protection)
        cookie.setSecure(secure); // Only sent over HTTPS in production
        cookie.setPath(path);
        cookie.setMaxAge(cookieMaxAge);

        if (!domain.isEmpty()) {
            cookie.setDomain(domain);
        }

        // Set SameSite attribute manually (not directly supported in older Cookie API)
        String cookieHeader = String.format(
                "%s=%s; Path=%s; Max-Age=%d; HttpOnly; %s SameSite=%s",
                cookieName, token, path, cookieMaxAge,
                secure ? "Secure;" : "",
                sameSite);

        response.addHeader("Set-Cookie", cookieHeader);
    }

    /**
     * Extract JWT token from cookies
     */
    public Optional<String> getTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return Optional.empty();
        }

        return Arrays.stream(request.getCookies())
                .filter(cookie -> cookieName.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }

    /**
     * Delete token cookie (for logout)
     */
    public void deleteTokenCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath(path);
        cookie.setMaxAge(0); // Delete immediately

        if (!domain.isEmpty()) {
            cookie.setDomain(domain);
        }

        response.addCookie(cookie);
    }
}