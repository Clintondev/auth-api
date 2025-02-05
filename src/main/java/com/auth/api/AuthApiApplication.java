// src/main/java/com/auth/api/AuthApiApplication.java
package com.auth.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class AuthApiApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthApiApplication.class, args);
    }
}
