package com.example.springjwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {
        // 모든 경로에 대해 CORS 설정을 적용함
        corsRegistry.addMapping("/**")
                .allowedOrigins("http://localhost:3000")  // 허용할 도메인 설정
                .allowedMethods("*")  // 모든 HTTP 메서드를 허용 (GET, POST, PUT, DELETE 등)
                .allowedHeaders("*")  // 모든 헤더를 허용
                .allowCredentials(true);  // 자격 증명(쿠키, 인증정보 등)을 허용
    }
}
