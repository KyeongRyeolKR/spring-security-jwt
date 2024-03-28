package com.example.securityjwt.config;

import com.example.securityjwt.jwt.CustomLogoutFilter;
import com.example.securityjwt.jwt.JwtFilter;
import com.example.securityjwt.jwt.JwtUtil;
import com.example.securityjwt.jwt.LoginFilter;
import com.example.securityjwt.repository.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
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
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CORS 설정 - 웹 브라우저에서 출처가 다른 곳에서 자원을 공유하는걸 허락하기 위한 설정
                // Spring MVC 외부 CORS 설정 -> ex) LoginFilter
                .cors(
                        (cors) -> cors
                                .configurationSource(new CorsConfigurationSource() {
                                    @Override
                                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                                        CorsConfiguration config = new CorsConfiguration();
                                        config.setAllowedOrigins(List.of("http://localhoast:3000")); // 허용할 경로
                                        config.setAllowedMethods(List.of("*")); // 허용할 메서드(GET, POST, ...)
                                        config.setAllowCredentials(true);
                                        config.setAllowedHeaders(List.of("*")); // 허용할 헤더
                                        config.setMaxAge(3600L); // 허용할 시간
                                        config.setExposedHeaders(List.of("Authorization")); // 최종 반환할 헤더
                                        return config;
                                    }
                                })
                );

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
                                .requestMatchers("/reissue").permitAll()
                                .anyRequest().authenticated()
                );

        http
                // 필터 등록 - LoginFilter 이전에 실행
                .addFilterBefore(new JwtFilter(jwtUtil), LoginFilter.class);

        http
                // 필터 등록 - UsernamePasswordAuthenticationFilter을 LoginFilter로 대체
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, refreshTokenRepository), UsernamePasswordAuthenticationFilter.class);

        http
                // 필터 등록 - LogoutFilter 이전에 실행
                .addFilterBefore(new CustomLogoutFilter(jwtUtil, refreshTokenRepository), LogoutFilter.class);

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
