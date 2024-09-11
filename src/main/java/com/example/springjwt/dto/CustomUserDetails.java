package com.example.springjwt.dto;

import com.example.springjwt.entity.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

/**
 * 간단한 설명:
 * CustomUserDetails 클래스는 UserDetails 인터페이스를 구현하여 Spring Security에서 사용자의 인증 정보를 관리할 수 있게 해줌.
 * getAuthorities: 사용자의 권한(roles)을 반환하는 메소드로, GrantedAuthority 객체를 생성하여 역할을 설정함.
 * getPassword, getUsername: 각각 사용자의 비밀번호와 아이디를 반환함.
 * isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired, isEnabled: 계정 상태를 관리하는 메소드들로,
 * 모두 true로 설정되어 계정이 만료되거나 잠겨있지 않으며, 항상 활성화 상태로 간주됨.
 * */

public class CustomUserDetails implements UserDetails {

    private final UserEntity userEntity;  // UserEntity 객체를 저장. 이 객체에는 데이터베이스에서 조회된 사용자 정보가 담겨 있음.

    // 생성자: UserEntity 객체를 받아서 userEntity 필드에 저장.
    public CustomUserDetails(UserEntity userData) {
        this.userEntity = userData;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 사용자의 권한(roles)을 반환. Spring Security는 권한(GrantedAuthority)이라는 인터페이스를 사용해 역할(Role)을 표현함.
        Collection<GrantedAuthority> collection = new ArrayList<>();

        // 사용자 엔티티의 role 값을 GrantedAuthority로 변환하여 컬렉션에 추가.
        collection.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return "ROLE_" + userEntity.getRole();  // 예: ROLE_ADMIN
            }
        });

        return collection;  // 사용자에게 부여된 권한의 목록을 반환.
    }

    @Override
    public String getPassword() {
        return userEntity.getPassword();  // 사용자 엔티티에서 비밀번호를 반환.
    }

    @Override
    public String getUsername() {
        return userEntity.getUsername();  // 사용자 엔티티에서 사용자 이름(아이디)를 반환.
    }

    // 계정이 만료되지 않았는지 여부를 반환. true로 설정되어 있으므로 항상 만료되지 않은 상태로 간주됨.
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정이 잠겨 있지 않은지 여부를 반환. true로 설정되어 있으므로 계정이 잠겨있지 않음.
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 비밀번호(인증 정보)가 만료되지 않았는지 여부를 반환. true로 설정되어 있으므로 인증 정보는 항상 유효한 상태로 간주됨.
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정이 활성화(사용 가능) 상태인지 여부를 반환. true로 설정되어 있으므로 계정은 항상 활성화 상태로 간주됨.
    @Override
    public boolean isEnabled() {
        return true;
    }
}
