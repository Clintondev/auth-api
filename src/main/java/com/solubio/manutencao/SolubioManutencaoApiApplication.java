// src/main/java/com/solubio/manutencao/SolubioManutencaoApiApplication.java
package com.solubio.manutencao;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class SolubioManutencaoApiApplication {
    public static void main(String[] args) {
        SpringApplication.run(SolubioManutencaoApiApplication.class, args);
    }
}