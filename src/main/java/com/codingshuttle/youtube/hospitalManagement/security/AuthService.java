package com.codingshuttle.youtube.hospitalManagement.security;

import com.codingshuttle.youtube.hospitalManagement.dto.LoginRequestDto;
import com.codingshuttle.youtube.hospitalManagement.dto.LoginResponseDto;
import com.codingshuttle.youtube.hospitalManagement.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import com.codingshuttle.youtube.hospitalManagement.dto.SignupResponseDto;
import com.codingshuttle.youtube.hospitalManagement.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;

@Service
@RequiredArgsConstructor
public class AuthService {

        private final AuthenticationManager authenticationManager;
        private final JwtService jwtService;
        private final UserRepository userRepository;
        private final PasswordEncoder passwordEncoder;

        public LoginResponseDto login(LoginRequestDto loginRequestDto) {

                Authentication authentication = authenticationManager.authenticate(
                                new UsernamePasswordAuthenticationToken(
                                                loginRequestDto.getUsername(),
                                                loginRequestDto.getPassword()));

                User user = (User) authentication.getPrincipal();

                String token = jwtService.generateToken(user);

                return new LoginResponseDto(
                                token,
                                user.getId());
        }

        public SignupResponseDto signup(LoginRequestDto SignupRequestDto) {
                User user = userRepository.findByUsername(SignupRequestDto.getUsername()).orElse(null);

                if (user != null)
                        throw new IllegalArgumentException("User already exists");

                user = userRepository.save(User.builder()
                                .username(SignupRequestDto.getUsername())
                                .password(passwordEncoder.encode(SignupRequestDto.getPassword()))
                                .build());

                return new SignupResponseDto(user.getId(), user.getUsername());
        }
}
