package com.greenloop.auth_service.unit.util;

import com.greenloop.auth_service.util.CookieUtil;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class CookieUtilTest {

    private final CookieUtil cookieUtil = new CookieUtil();

    @BeforeEach
    void setUp() {
        // Inject defaults since we're not using a Spring context here
        ReflectionTestUtils.setField(cookieUtil, "cookieName", "AUTH_TOKEN");
        ReflectionTestUtils.setField(cookieUtil, "cookieMaxAge", 86400);
        ReflectionTestUtils.setField(cookieUtil, "secure", false);
        ReflectionTestUtils.setField(cookieUtil, "sameSite", "Lax");
        ReflectionTestUtils.setField(cookieUtil, "domain", "");
        ReflectionTestUtils.setField(cookieUtil, "path", "/");
    }

    @Test
    void addAndReadTokenCookie_Succeeds() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        cookieUtil.addTokenCookie(response, "abc.def.ghi");

        // addTokenCookie uses Set-Cookie header for SameSite support
        String setCookie = response.getHeader("Set-Cookie");
        assertNotNull(setCookie);
        assertTrue(setCookie.contains("AUTH_TOKEN=abc.def.ghi"));
        assertTrue(setCookie.contains("HttpOnly"));
        assertTrue(setCookie.contains("Path=/"));

        // Verify extraction from incoming request cookies
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("AUTH_TOKEN", "abc.def.ghi"));

        Optional<String> token = cookieUtil.getTokenFromCookie(request);
        assertTrue(token.isPresent());
        assertEquals("abc.def.ghi", token.get());
    }

    @Test
    void deleteTokenCookie_SetsExpiredCookie() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        cookieUtil.deleteTokenCookie(response);

        assertNotNull(response.getCookie("AUTH_TOKEN"));
        assertEquals(0, response.getCookie("AUTH_TOKEN").getMaxAge());
        assertEquals("", response.getCookie("AUTH_TOKEN").getValue());
    }
}
