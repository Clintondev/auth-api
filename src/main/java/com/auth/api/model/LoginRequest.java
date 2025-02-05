//src/main/java/com/auth/api/model/LoginRequest.java
package com.auth.api.model;

import lombok.Data;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

@Data
public class LoginRequest {
    @NotBlank(message = "O e-mail é obrigatório.")
    @Email(message = "Formato de e-mail inválido.")
    private String email;

    @NotBlank(message = "A senha é obrigatória.")
    private String password;

    private Integer twoFactorCode; 
}
