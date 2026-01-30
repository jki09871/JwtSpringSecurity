알겠어 브로 👍
아래 내용은 **그대로 GitHub README.md에 붙여도 되는 마크다운(markdown)** 이고,
**실제 네가 구현한 JWT + Spring Security 구조 기준**으로 다시 정리했어.

---

````md
# Spring Boot JWT Authentication Example

## 📌 개요

이 프로젝트는 **Spring Boot 3.x + Spring Security 6** 환경에서  
**JWT(JSON Web Token)** 기반 인증/인가를 구현한 예제입니다.

- 로그인 성공 시 **JWT Access Token 발급**
- JWT를 이용한 **Stateless 인증**
- **ROLE 기반 접근 제어** (`ROLE_ADMIN`)
- **BCrypt** 비밀번호 암호화
- **MySQL + JPA** 사용자 관리
- **Custom Login Filter + JWT Filter** 구조

---

## 🚀 주요 기능

- JWT 기반 로그인 인증
- ROLE 기반 접근 제어 (`/admin`)
- BCrypt 비밀번호 암호화
- Spring Security FilterChain 직접 구성
- 세션 미사용 (STATELESS)
- JSON 로그인 지원
- CORS / OPTIONS Preflight 처리

---

## 🧱 기술 스택

- Java 17
- Spring Boot 3.3.3
- Spring Security 6.x
- JWT (io.jsonwebtoken 0.12.3)
- Spring Data JPA
- MySQL
- Lombok
- Gradle

---

## ⚙️ 프로젝트 설정

### 1️⃣ 저장소 클론

```bash
git clone https://github.com/jki09871/JwtSpringSecurity.git
cd JwtSpringSecurity
````

---

### 2️⃣ MySQL 설정

`src/main/resources/application.properties`

```properties
spring.datasource.url=jdbc:mysql://localhost:3306/your_db_name
spring.datasource.username=your_username
spring.datasource.password=your_password
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver

spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQLDialect
```

---

### 3️⃣ JWT 시크릿 키 설정

```properties
spring.jwt.secret=your_secret_key_here
```

> ⚠️ 실제 운영에서는 환경 변수 또는 Vault 사용 권장

---

### 4️⃣ Gradle 의존성 설정

```gradle
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.3.3'
    id 'io.spring.dependency-management' version '1.1.6'
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'org.springframework.boot:spring-boot-starter-web'

    runtimeOnly 'com.mysql:mysql-connector-j'

    implementation 'io.jsonwebtoken:jjwt-api:0.12.3'
    implementation 'io.jsonwebtoken:jjwt-impl:0.12.3'
    implementation 'io.jsonwebtoken:jjwt-jackson:0.12.3'

    compileOnly 'org.projectlombok:lombok'
    annotationProcessor 'org.projectlombok:lombok'

    testImplementation 'org.springframework.boot:spring-boot-starter-test'
    testImplementation 'org.springframework.security:spring-security-test'
}
```

---

## 🔐 API 설명

---

### 1️⃣ 회원가입

**URL**

```
POST /join
```

**설명**

* 사용자 정보를 받아 DB에 저장
* 비밀번호는 BCrypt로 암호화됨

```java
@PostMapping("/join")
public String joinProcess(JoinDTO joinDTO) {
    joinService.joinProcess(joinDTO);
    return "ok";
}
```

---

### 2️⃣ 로그인 (JWT 발급)

**URL**

```
POST /login
```

**Content-Type**

```
application/json
```

**Request Body**

```json
{
  "username": "hong",
  "password": "1228"
}
```

**설명**

* 로그인 성공 시 JWT 토큰을 생성
* 응답 헤더 `Authorization` 에 토큰 포함

```java
@Override
protected void successfulAuthentication(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain chain,
        Authentication authentication) throws IOException {

    CustomUserDetails userDetails =
            (CustomUserDetails) authentication.getPrincipal();

    String token = jwtUtil.createJwt(
            userDetails.getUsername(),
            userDetails.getRole(),
            1000 * 60 * 60 * 10L // 10시간
    );

    response.addHeader("Authorization", "Bearer " + token);
}
```

---

### 3️⃣ 관리자 페이지 접근 (ROLE_ADMIN)

**URL**

```
GET /admin
```

**설명**

* `ROLE_ADMIN` 권한이 있는 사용자만 접근 가능

```java
@GetMapping("/admin")
public String adminP() {
    return "Admin Controller";
}
```

---

### 4️⃣ 메인 페이지 (인증 확인)

**URL**

```
GET /
```

**설명**

* JWT 토큰을 통해 인증된 사용자 정보 확인

```java
@GetMapping("/")
public String mainP() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    return "User: " + auth.getName() + " / Role: " + auth.getAuthorities();
}
```

---

## 🧩 JWT 처리 구조

---

### JwtUtil

* JWT 생성
* 클레임에서 username / role 추출
* 만료 시간 검증

```java
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

---

### JWTFilter

* Authorization 헤더에서 JWT 추출
* 토큰 검증
* SecurityContextHolder에 인증 객체 저장

```java
@Override
protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain) throws IOException, ServletException {

    String authorization = request.getHeader("Authorization");

    if (authorization == null || !authorization.startsWith("Bearer ")) {
        filterChain.doFilter(request, response);
        return;
    }

    String token = authorization.substring(7);

    if (jwtUtil.isExpired(token)) {
        filterChain.doFilter(request, response);
        return;
    }

    String username = jwtUtil.getUsername(token);
    String role = jwtUtil.getRole(token);

    UserEntity user = new UserEntity();
    user.setUsername(username);
    user.setRole(role);

    CustomUserDetails userDetails = new CustomUserDetails(user);

    Authentication authToken =
            new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );

    SecurityContextHolder.getContext().setAuthentication(authToken);
    filterChain.doFilter(request, response);
}
```

---

## 📬 Postman 사용 방법

### 1️⃣ 로그인

* Method: `POST`
* URL: `http://localhost:8080/login`
* Headers:

```
Content-Type: application/json
```

* Body (raw / JSON)

```json
{
  "username": "hong",
  "password": "1228"
}
```

➡️ **응답 헤더에서 Authorization 값 복사**

---

### 2️⃣ 인증 API 호출

* Method: `GET`
* URL: `http://localhost:8080/admin`
* Headers:

```
Authorization: Bearer {JWT_TOKEN}
```

---

## ⚠️ 주의사항

* `hasRole("ADMIN")` → 내부적으로 `ROLE_` 자동 추가
* `hasAuthority("ROLE_ADMIN")` → 그대로 비교
* JWT 만료 시간은 **밀리초(ms)** 기준
* 로그인 요청은 반드시 **JSON Body** 사용

---

## ✅ 정리

* JWT + Security 구조 이해용 예제
* 실무에서 그대로 확장 가능
* Refresh Token / Redis 연동 등 추가 가능

---

📌 **JWT 인증 구조 학습용으로 강력 추천**

```
