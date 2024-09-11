package com.example.springjwt.service;

import com.example.springjwt.dto.joinDTO;
import com.example.springjwt.entity.UserEntity;
import com.example.springjwt.repsository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;



    public void joinProcess(joinDTO joinDTO){

        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();
        
        // 회원 아이디 중복 확인
        boolean isExist = userRepository.existsByUsername(username);
        
        if (isExist){
            
            return;
        }

        UserEntity data = new UserEntity();
        
        data.setUsername(username);
        data.setPassword(bCryptPasswordEncoder.encode(password));
        data.setRole("ADMIN");
        
        userRepository.save(data);

    }
}
