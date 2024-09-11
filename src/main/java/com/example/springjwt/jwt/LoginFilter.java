package com.example.springjwt.jwt;

import com.example.springjwt.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

/**
 * 간단한 설명:
 * attemptAuthentication: 요청으로부터 username과 password를 추출한 후 UsernamePasswordAuthenticationToken을 생성하여,
 * AuthenticationManager를 사용해 인증을 시도함.
 * successfulAuthentication: 인증 성공 시 사용자 정보에서 username과 role을 추출하여, JWT 토큰을 생성한 뒤, 응답 헤더에 토큰을 추가함.
 * unsuccessfulAuthentication: 인증 실패 시, 401 상태 코드로 응답을 반환함.
 * 이 클래스는 Spring Security에서 인증 절차를 처리하고, 인증이 성공하면 JWT 토큰을 생성하여 클라이언트에게 전달하는 역할을 함이다.
 * */

@RequiredArgsConstructor  // Lombok을 사용하여 필요한 필드를 생성자로 주입받도록 설정. (AuthenticationManager와 JwtUtil)
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationMa;  // 인증을 처리할 매니저.
    private final JwtUtil jwtUtil;  // JWT 토큰을 생성하고 검증하는 유틸리티 클래스.

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 클라이언트 요청에서 username과 password를 추출함.
        String username = obtainUsername(request);  // request에서 username 파라미터를 추출.
        String password = obtainPassword(request);  // request에서 password 파라미터를 추출.

        // 사용자 이름과 비밀번호를 담은 인증 토큰을 생성. 아직 인증되지 않은 상태임.
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        // AuthenticationManager를 통해 사용자가 입력한 인증 정보를 검증함.
        return authenticationMa.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        // 인증 성공 시 호출되는 메소드. JWT 토큰을 생성하여 클라이언트에게 반환하는 역할을 함.

        // 인증된 사용자의 정보를 CustomUserDetails 객체로 변환.
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        // 사용자 이름(username)을 가져옴.
        String username = userDetails.getUsername();

        // 사용자의 권한(roles)을 가져옴.
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();  // 첫 번째 권한(예: ROLE_USER, ROLE_ADMIN)을 가져옴.

        // JWT 토큰 생성. 유효 시간은 10시간(60 * 60 * 10).
        String role = auth.getAuthority();
        String token = jwtUtil.createJwt(username, role, 60 * 60 * 10L);


        // 응답 헤더에 생성된 JWT 토큰을 추가.
        response.addHeader("Authorization", "Bearer " + token);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        // 인증 실패 시 호출되는 메소드. 401 상태 코드를 클라이언트에 반환하여 인증 실패를 알림.
        response.setStatus(401);  // 401 Unauthorized 상태 코드 반환.
    }
}

