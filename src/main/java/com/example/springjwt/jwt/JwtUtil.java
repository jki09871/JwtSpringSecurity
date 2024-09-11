package com.example.springjwt.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * secretKey 설정: 생성자에서 주입된 비밀 문자열을 기반으로 JWT 서명 및 검증에 사용할 secretKey를 설정함.
 * getUsername, getRole: 각각 JWT 토큰에서 "username"과 "role" 정보를 추출하는 역할을 함.
 * isExpired: 토큰의 만료 시간을 확인하고, 현재 시간과 비교하여 만료 여부를 반환함.
 * createJwt: 사용자 이름, 역할, 만료 시간(밀리초 단위)을 받아 새로운 JWT 토큰을 생성하여 반환함.
 * */

@Component  // 스프링에서 이 클래스를 빈으로 등록함. 다른 곳에서 @Autowired로 주입받을 수 있음.
public class JwtUtil {

    private SecretKey secretKey;  // JWT 토큰을 서명하고 검증하는 데 사용할 비밀키.

    // 생성자에서 설정 파일(application.properties 또는 application.yml)에 있는 비밀키를 가져와 SecretKey 객체로 변환함.
    private JwtUtil(@Value("${spring.jwt.secret}") String secret) {

        // 주어진 비밀 문자열(secret)을 UTF-8로 변환한 후 HMAC SHA-256 알고리즘을 사용한 SecretKeySpec 객체로 변환.
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // JWT 토큰에서 username을 추출하는 메소드.
    public String getUsername(String token) {

        // 비밀키를 이용해 서명된 JWT 토큰을 파싱하고, 'username' 필드 값을 가져옴.
        return Jwts.parser()
                .verifyWith(secretKey)  // 비밀키를 사용해 서명 검증.
                .build()
                .parseSignedClaims(token)  // JWT 토큰을 파싱하여 서명된 클레임을 가져옴.
                .getPayload()
                .get("username", String.class);  // username 필드에서 값을 추출.
    }

    // JWT 토큰에서 role을 추출하는 메소드.
    public String getRole(String token) {
        // 비밀키를 이용해 서명된 JWT 토큰을 파싱하고, 'role' 필드 값을 가져옴.
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("role", String.class);  // role 필드에서 값을 추출.
    }

    // JWT 토큰이 만료되었는지 확인하는 메소드.
    public Boolean isExpired(String token) {
        // 비밀키를 이용해 서명된 JWT 토큰을 파싱하고, 만료 시간을 확인하여 현재 시간과 비교함.
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration()  // 토큰의 만료 시간을 가져옴.
                .before(new Date());  // 만료 시간이 현재 시간보다 이전인지 확인.
    }

    // 새로운 JWT 토큰을 생성하는 메소드.
    public String createJwt(String username, String role, Long expiredMs) {
        return Jwts.builder()
                .claim("username", username)  // 'username' 정보를 클레임에 추가.
                .claim("role", "ROLE_" + role)  // ROLE_ 접두사 추가
                .issuedAt(new Date(System.currentTimeMillis()))  // 현재 시간을 발행 시간으로 설정.
                .expiration(new Date(System.currentTimeMillis() + expiredMs))  // 만료 시간을 현재 시간 + expiredMs 밀리초로 설정.
                .signWith(secretKey)  // 비밀키를 사용해 서명.
                .compact();  // JWT 토큰 문자열을 최종 생성.
    }
}
