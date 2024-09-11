package com.example.springjwt.jwt;

import com.example.springjwt.dto.CustomUserDetails;
import com.example.springjwt.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 간단한 설명:
 * Authorization 헤더 확인: 요청에서 Authorization 헤더를 추출하고, 값이 Bearer 로 시작하지 않으면 필터 체인을 계속 진행하며 아무 작업도 하지 않음.
 * 토큰 유효성 검사: Authorization 헤더에서 Bearer 접두사를 제거한 후 토큰을 추출. 그 토큰이 만료되었는지 확인.
 * 사용자 정보 추출: 토큰에서 username과 role을 추출하고, 이를 기반으로 UserEntity 객체를 생성하여 임시 비밀번호와 함께 CustomUserDetails에 저장.
 * 스프링 시큐리티 인증 토큰 생성: UsernamePasswordAuthenticationToken을 생성하고, SecurityContextHolder에 설정하여 스프링 시큐리티에 인증된 사용자로 등록.
 * 필터 체인 진행: 마지막으로 필터 체인에서 다음 필터로 요청을 넘김.
 * 이 필터는 각 요청마다 JWT 토큰을 확인하고, 유효한 경우 스프링 시큐리티 컨텍스트에 사용자를 인증된 상태로 등록함이다.
 * */
@RequiredArgsConstructor  // Lombok을 사용해 필요한 의존성을 생성자 주입으로 설정.
public class JWTFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;  // JWT 토큰의 유효성 검사 및 토큰에서 정보 추출을 위한 유틸리티 클래스.

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //request에서 Authorization 헤더를 찾음
        String authorization= request.getHeader("Authorization");

        //Authorization 헤더 검증
        if (authorization == null || !authorization.startsWith("Bearer ")) {

            System.out.println("token null");
            filterChain.doFilter(request, response);

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        System.out.println("authorization now");
        //Bearer 부분 제거 후 순수 토큰만 획득
        String token = authorization.split(" ")[1];

        //토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) {

            System.out.println("token expired");
            filterChain.doFilter(request, response);

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        //토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        //userEntity를 생성하여 값 set
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temppassword");
        userEntity.setRole(role);

        //UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        //스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
