package com.example.springjwt.config;

import com.example.springjwt.jwt.JWTFilter;
import com.example.springjwt.jwt.JwtUtil;
import com.example.springjwt.jwt.LoginFilter;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration  // 이 클래스가 스프링의 설정 클래스를 나타냄. 이 어노테이션을 통해 스프링이 해당 클래스를 설정 파일로 인식함.
@EnableWebSecurity  // 스프링 시큐리티를 활성화하는 어노테이션. 시큐리티 설정을 적용하기 위해 필수적으로 필요함.
@RequiredArgsConstructor  // Lombok 어노테이션으로, 의존성 주입을 생성자 주입 방식으로 처리함. 필요한 필드를 자동으로 주입하는 생성자를 생성해줌.
public class SecurityConfig {
    private final AuthenticationConfiguration authenticationConfiguration;  // AuthenticationManager 생성을 위해 필요한 설정을 담고 있는 객체.
    private final JwtUtil jwtUtil;  // JWT 토큰 처리 관련 유틸리티 클래스.

    @Bean  // BCryptPasswordEncoder를 스프링 컨텍스트에 빈으로 등록. 비밀번호를 암호화하는 데 사용됨.
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();  // BCrypt 알고리즘을 사용한 비밀번호 암호화 인코더를 반환.
    }

    @Bean  // AuthenticationManager를 스프링 컨텍스트에 빈으로 등록. 사용자 인증 처리에 사용됨.
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();  // AuthenticationManager를 스프링 시큐리티 설정에서 가져옴.
    }

    @Bean  // SecurityFilterChain을 스프링 컨텍스트에 빈으로 등록하여 시큐리티의 필터 체인을 설정함.
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // CORS 설정을 추가. 클라이언트 도메인(`http://localhost:3000`)과의 요청을 허용.
        http.cors((cors) -> cors
                .configurationSource(new CorsConfigurationSource() {

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration configuration = new CorsConfiguration();
                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));  // 허용할 도메인 설정.
                        configuration.setAllowedMethods(Collections.singletonList("*"));  // 모든 HTTP 메서드를 허용.
                        configuration.setAllowCredentials(true);  // 자격 증명을 포함한 요청을 허용.
                        configuration.setAllowedHeaders(Collections.singletonList("*"));  // 모든 헤더를 허용.
                        configuration.setMaxAge(3600L);  // 캐시 유효 시간 설정(1시간).
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));  // 클라이언트가 접근할 수 있는 헤더를 지정.

                        return configuration;
                    }
                }));

        // CSRF 보호를 비활성화. JWT 토큰 기반 인증에서는 CSRF 토큰이 불필요하기 때문에 비활성화함.
        http.csrf((auth) -> auth.disable());

        // 기본 제공되는 폼 로그인 방식을 비활성화함.
        http.formLogin((auth) -> auth.disable());

        // HTTP 기본 인증 방식을 비활성화함. 대신 JWT 기반 인증을 사용함.
        http.httpBasic((auth) -> auth.disable());

        // URL별 접근 권한 설정. 지정된 경로에 대한 권한을 설정함.
        http.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/login", "/", "/join").permitAll()  // 누구나 접근 가능한 경로들.
                .requestMatchers("/admin").hasRole("ADMIN")  // ADMIN 역할이 있어야 접근 가능한 경로.
                .anyRequest().authenticated());  // 그 외의 모든 요청은 인증된 사용자만 접근 가능.

        // JWTFilter를 LoginFilter 이전에 실행되도록 설정. JWT 토큰을 먼저 처리한 후 로그인 필터를 실행함.
        http.addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        // 커스텀 로그인 필터(LoginFilter)를 UsernamePasswordAuthenticationFilter 위치에 추가. 인증을 이 필터에서 처리함.
        http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // 세션을 사용하지 않도록 설정. JWT 같은 토큰 기반 인증 방식을 사용하므로 세션을 비활성화하고 Stateless 방식으로 설정함.
        http.sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();  // 설정한 시큐리티 필터 체인을 빌드하여 반환.
    }
}


