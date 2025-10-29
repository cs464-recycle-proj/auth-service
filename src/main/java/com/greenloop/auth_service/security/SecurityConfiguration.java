package com.greenloop.auth_service.security;

import com.greenloop.auth_service.util.CookieUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Spring Security configuration for stateless JWT authentication.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

        private final JwtAuthFilter jwtAuthFilter;
        private final AuthenticationProvider authenticationProvider;
        private final CookieUtil cookieUtil;

        /**
         * Configures HTTP security with public, admin, and authenticated routes.
         */
        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                .csrf(AbstractHttpConfigurer::disable) // Consider enabling CSRF with cookie-based auth
                                .authorizeHttpRequests(auth -> auth
                                                // Public endpoints
                                                .requestMatchers(
                                                                "/actuator/health",
                                                                "/api/auth/signup",
                                                                "/api/auth/login",
                                                                "/api/verify/**")
                                                .permitAll()

                                                // Admin-only endpoints
                                                .requestMatchers("/api/auth/admin/signup").hasRole("ADMIN")

                                                // All other requests require authentication
                                                .anyRequest().authenticated())

                                .sessionManagement(sess -> sess
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                                .authenticationProvider(authenticationProvider)
                                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                                .logout(logout -> logout
                                                .logoutUrl("/api/auth/logout")
                                                .logoutSuccessHandler((request, response, authentication) -> {
                                                        SecurityContextHolder.clearContext();
                                                        // Delete the auth cookie
                                                        cookieUtil.deleteTokenCookie(response);
                                                        response.setStatus(HttpStatus.OK.value());
                                                        response.setContentType("application/json");
                                                        response.getWriter()
                                                                        .write("{\"message\":\"Logout successful\"}");
                                                })
                                                .invalidateHttpSession(false));

                return http.build();
        }
}