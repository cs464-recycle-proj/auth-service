package com.greenloop.auth_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the Auth Service application.
 * <p>
 * This service is responsible for user authentication, registration, and
 * verification. It issues JWTs that are consumed by the API gateway and other
 * microservices.
 */
@SpringBootApplication
public class AuthServiceApplication {

	/**
	 * Boots the Spring application.
	 *
	 * @param args CLI args
	 */
	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
	}

}
