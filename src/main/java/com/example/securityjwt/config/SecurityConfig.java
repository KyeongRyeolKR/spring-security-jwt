package com.example.securityjwt.config;

import com.example.securityjwt.jwt.JwtUtil;
import com.example.securityjwt.jwt.LoginFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtil jwtUtil;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // STATELESS Session 방식이기 때문에 CSRF가 필요 없으므로 disable 설정
        http.csrf(AbstractHttpConfigurer::disable);

        // JWT 로그인 방식이기 때문에 폼 로그인 disable 설정
        http.formLogin(AbstractHttpConfigurer::disable);

        // JWT 로그인 방식이기 떄문에 HTTP Basic 로그인 disable 설정
        http.httpBasic(AbstractHttpConfigurer::disable);

        http
                .authorizeHttpRequests(
                        (auth) -> auth
                                .requestMatchers("/login", "/", "/join").permitAll()
                                .requestMatchers("/admin").hasRole("ADMIN")
                                .anyRequest().authenticated()
                );

        http
                // 필터 등록 - UsernamePasswordAuthenticationFilter을 LoginFilter로 대체
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        http
                // Session STATELESS 설정
                .sessionManagement(
                        (session) -> session
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
