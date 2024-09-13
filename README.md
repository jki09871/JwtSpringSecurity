# Spring Boot JWT Authentication Example

## 개요

이 프로젝트는 **Spring Boot**를 사용하여 **JWT** 기반 인증을 구현한 예제입니다. 사용자는 회원 가입 후 JWT를 통해 인증할 수 있으며, 권한(Role)에 따라 접근이 제한되는 API도 포함되어
있습니다. 또한, **BCrypt**를 사용한 비밀번호 암호화와 **Spring Security**를 사용한 인증 처리를 지원합니다.

## 주요 기능

- **JWT**를 사용한 사용자 인증 및 권한 관리
- **BCrypt**를 사용한 비밀번호 암호화
- **Spring Security**를 사용한 인증 및 인가 처리
- **MySQL**을 사용하여 사용자 데이터 관리
- CORS 설정을 통해 특정 도메인에서만 요청 허용
- 사용자 가입, 로그인, 권한에 따른 접근 제어

## 기술 스택

- **Java 17**
- **Spring Boot 3.3.3**
- **Spring Security**
- **JWT (io.jsonwebtoken)**
- **MySQL**
- **BCrypt**
- **Lombok**
- **Maven Central**

## 프로젝트 설정

### 1. 저장소 클론

다음 명령어로 프로젝트를 클론

```bash
git clone https://github.com/jki09871/JwtSpringSecurity.git
cd spring-jwt-auth
```

### 2. MySQL 설정

프로젝트에서 MySQL을 사용하기 때문에, 데이터베이스 설정을 src/main/resources/application.properties 파일에 추가

```
spring.datasource.url=jdbc:mysql://localhost:3306/your_db_name
spring.datasource.username=your_username
spring.datasource.password=your_password
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true

```

### 3. JWT 시크릿 키 설정
JWT 토큰 서명에 사용할 시크릿 키를 application.properties 파일에 추가
```
spring.jwt.secret=your_secret_key
```

### 4. Gradle 의존성 설정
프로젝트의 build.gradle 파일에는 다음과 같은 의존성을 추가
```
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.3.3'
    id 'io.spring.dependency-management' version '1.1.6'
}

group = 'com.example'
version = '0.0.1-SNAPSHOT'

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'org.springframework.boot:spring-boot-starter-web'
    compileOnly 'org.projectlombok:lombok'
    runtimeOnly 'com.mysql:mysql-connector-j'

    // JWT 관련 라이브러리
    implementation 'io.jsonwebtoken:jjwt-api:0.12.3'
    implementation 'io.jsonwebtoken:jjwt-impl:0.12.3'
    implementation 'io.jsonwebtoken:jjwt-jackson:0.12.3'

    annotationProcessor 'org.projectlombok:lombok'
    testImplementation 'org.springframework.boot:spring-boot-starter-test'
    testImplementation 'org.springframework.security:spring-security-test'
    testRuntimeOnly 'org.junit.platform:junit-platform-launcher'
}

tasks.named('test') {
    useJUnitPlatform()
}
```

## API 설명

### 1. 사용자 가입
   URL: /join
   Method: POST
   Description: 사용자 정보를 받아 MySQL 데이터베이스에 저장하고, 암호화된 비밀번호로 저장
```
@PostMapping("/join")
public String joinProcess(joinDTO joinDTO) {
    joinService.joinProcess(joinDTO);
    return "ok";
}
```

### 2. 사용자 로그인
URL: /login
Method: POST
Description: 사용자 인증 정보를 받아 JWT 토큰을 생성하여 응답 헤더에 추가
```
@Override
protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
    CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
    String token = jwtUtil.createJwt(userDetails.getUsername(), userDetails.getAuthorities().toString(), 60 * 60 * 10L);
    response.addHeader("Authorization", "Bearer " + token);
}
```

### 3. 관리자 페이지 접근 (ROLE_ADMIN)
URL: /admin
Method: GET
Description: ROLE_ADMIN 권한을 가진 사용자만 접근할 수 있다.
```
@GetMapping("/admin")
public String adminP() {
    return "Admin Controller";
}
```

### 4. 메인 페이지 (권한 확인)
URL: /
Method: GET
Description: JWT 토큰을 통해 사용자 이름과 역할 정보를 반환
```
@GetMapping("/")
public String mainP() {
    String username = SecurityContextHolder.getContext().getAuthentication().getName();
    String role = SecurityContextHolder.getContext().getAuthentication().getAuthorities().toString();
    return "Main Controller: " + username + " Role: " + role;
}
```

## JWT 관련 클래스
### 1. JwtUtil
   JWT 생성, 유효성 검사 및 정보 추출을 담당하는 유틸리티 클래스
```
public String createJwt(String username, String role, Long expiredMs) {

return Jwts.builder()
        .claim("username", username)
        .claim("role", role)
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + expiredMs))
        .signWith(secretKey)
        .compact();
}
```

### 2. JWTFilter
JWT 토큰을 HTTP 요청에서 추출하고 유효성을 검사하여 Spring Security 컨텍스트에 저장하는 필터
```
@Override
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    String token = jwtUtil.getToken(request);
    if (token != null && jwtUtil.isValid(token)) {
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(username, null, role));
    }
    filterChain.doFilter(request, response);
}
```

