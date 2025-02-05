//src/main/java/com/auth/api/config/SwaggerConfig.java
package com.auth.api.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("API de Autenticação")
                        .version("1.0")
                        .description("Documentação da API.")
                        .contact(new Contact()
                                .name("Equipe api")
                                .email("seu_email@email.com.br")
                                .url("https://www.api.agr.br"))
                        .license(new License()
                                .name("Licença Apache 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0.html")));
    }
}