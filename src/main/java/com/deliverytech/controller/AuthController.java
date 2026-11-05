package com.deliverytech.controller;

import com.deliverytech.dto.request.LoginRequest;
import com.deliverytech.dto.request.RegisterRequest;
import com.deliverytech.model.Role;
import com.deliverytech.model.Usuario;
import com.deliverytech.repository.UsuarioRepository;
import com.deliverytech.security.JwtUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*") // 🌟 Resolve o bloqueio de CORS com o React localmente
@Tag(name = "Autenticação", description = "Endpoints para registro e login de usuários")
public class AuthController {

    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    @Operation(summary = "Registra um novo usuário", description = "Cria um novo usuário (cliente ou outro tipo) e retorna um token JWT para acesso.")
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        try {
            if (usuarioRepository.findByEmail(request.getEmail()).isPresent()) {
                return ResponseEntity.badRequest().body(Map.of("message", "Email já cadastrado"));
            }

            Usuario usuario = Usuario.builder()
                    .email(request.getEmail())
                    .senha(passwordEncoder.encode(request.getSenha()))
                    .nome(request.getNome())
                    .role(request.getRole() != null ? request.getRole() : Role.CLIENTE)
                    .ativo(true)
                    .restauranteId(request.getRestauranteId())
                    .build();

            usuarioRepository.save(usuario);
            
            String token = jwtUtil.generateToken(
                User.withUsername(usuario.getEmail())
                    .password(usuario.getSenha())
                    .authorities("ROLE_" + usuario.getRole().name())
                    .build(), 
                usuario
            );
            
            return ResponseEntity.ok(Map.of("token", token));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Erro inesperado ao registrar usuário: " + e.getMessage()));
        }
    }

    @Operation(summary = "Autentica um usuário", description = "Autentica um usuário com email e senha e retorna um token JWT válido.")
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            // 1. Tenta realizar a autenticação das credenciais com o Spring Security
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getSenha())
            );
            
            // 2. Recupera o usuário do banco de dados para gerar as claims adicionais do token
            Usuario usuario = usuarioRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new RuntimeException("Usuário não encontrado no banco de dados."));
                    
            // 3. Gera o Token JWT contendo as informações validadas
            String token = jwtUtil.generateToken(
                User.withUsername(usuario.getEmail())
                    .password(usuario.getSenha())
                    .authorities("ROLE_" + usuario.getRole().name())
                    .build(), 
                usuario
            );
            
            // Retorna o JSON estruturado esperado pelo Axios no React
            return ResponseEntity.ok(Map.of("token", token));

        } catch (AuthenticationException e) {
            // 🌟 Captura erros do Spring Security (como BadCredentialsException ou UsernameNotFoundException)
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "E-mail ou senha inválidos. Caso o servidor tenha reiniciado, lembre-se de recriar o usuário no Swagger."));
        } catch (RuntimeException e) {
            // Captura falhas se o usuário não for encontrado após a validação
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            // Captura qualquer outro tipo de erro sistêmico imprevisto
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "Erro inesperado no servidor: " + e.getMessage()));
        }
    }
}
