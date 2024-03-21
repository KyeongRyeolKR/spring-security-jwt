package com.example.securityjwt.controller;

import com.example.securityjwt.dto.JoinDto;
import com.example.securityjwt.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(JoinDto dto) {
        joinService.joinProcess(dto);

        return "ok";
    }
}
