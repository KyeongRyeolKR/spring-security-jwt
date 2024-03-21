package com.example.securityjwt.service;

import com.example.securityjwt.dto.JoinDto;
import com.example.securityjwt.entity.User;
import com.example.securityjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public void joinProcess(JoinDto dto) {
        if(userRepository.existsByUsername(dto.getUsername())) {
            return;
        }

        User user = new User();
        user.setUsername(dto.getUsername());
        user.setPassword(passwordEncoder.encode(dto.getPassword()));
        user.setRole("ROLE_ADMIN");

        userRepository.save(user);
    }
}
