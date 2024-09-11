package com.example.springjwt.controller;

import com.example.springjwt.dto.joinDTO;
import com.example.springjwt.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;


    @PostMapping("/join")
    public String joinProcess(joinDTO joinDTO){
        joinService.joinProcess(joinDTO);
        return "ok";
    }
}
