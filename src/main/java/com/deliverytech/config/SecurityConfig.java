package com.deliverytech.config;

import com.deliverytech.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Definindo uma lista de endpoints públicos que não exigem autenticação
        final String[] PUBLIC_ENDPOINTS = {
                "/api/auth/**",
                "/swagger-ui.html",
                "/swagger-ui/**",
                "/api-docs/**",
                "/h2-console/**",
                "/actuator/**" // Liberando todos os endpoints do Actuator
        };

        return http
                .csrf(csrf -> csrf.disable()) // Desabilita CSRF para APIs stateless
                .headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable())) // Permite o acesso ao H2 Console
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Garante sessões stateless
                .authorizeHttpRequests(auth -> auth
                        // Libera o acesso aos endpoints públicos definidos acima
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()

                        // Endpoints de Cliente
                        .requestMatchers("/api/clientes", "/clientes").hasAnyAuthority("ROLE_ADMIN", "ROLE_CLIENTE")
                        .requestMatchers("/api/clientes/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_CLIENTE")

                        // Endpoints de Pedido
                        .requestMatchers("/api/pedidos").hasAuthority("ROLE_CLIENTE")
                        .requestMatchers("/api/pedidos/**").hasAuthority("ROLE_CLIENTE")

                        // Endpoints de Restaurante e Produto
                        .requestMatchers("/api/restaurantes").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/api/restaurantes/**").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/api/produtos").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/api/produtos/**").hasAuthority("ROLE_ADMIN")

                        // Garante que qualquer outra requisição não listada seja autenticada
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class) // Adiciona o filtro JWT
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
}