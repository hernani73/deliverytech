package com.deliverytech.dto.request;

import com.deliverytech.model.Role;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {
    @Schema(example = "email@teste.com")
   @Email(message = "O formato do email é inválido")
    @NotBlank(message = "O email não pode ficar vazio")
    private String email;
    @Schema(example = "Senha@forte321")
    @Size(min = 6, message = "A senha deve ter no minimo 6 caracteres")
    @NotBlank(message = "A senha não pode estar em branco") 
    @Pattern(regexp = ".*[!@#$%&*()].*",message = "A senha deve conter pelo menos um caracter especial, exemplo:!@#$%&*() ")
    private String senha;

    @Schema(example = "Nome do usuário")
    @NotBlank(message = "O nome não pode estar em branco")
    private String nome;

    private Role role;
    private Long restauranteId;
}
