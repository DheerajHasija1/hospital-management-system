package com.codingshuttle.youtube.hospitalManagement.security;

import com.codingshuttle.youtube.hospitalManagement.dto.LoginRequestDto;
import com.codingshuttle.youtube.hospitalManagement.dto.LoginResponseDto;
import com.codingshuttle.youtube.hospitalManagement.entity.User;
import com.codingshuttle.youtube.hospitalManagement.entity.type.AuthProviderType;
import lombok.RequiredArgsConstructor;
import java.security.AuthProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import com.codingshuttle.youtube.hospitalManagement.dto.SignupResponseDto;
import com.codingshuttle.youtube.hospitalManagement.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;

@Service
@RequiredArgsConstructor
public class AuthService {

        private final AuthenticationManager authenticationManager;
        private final JwtService jwtService;
        private final UserRepository userRepository;
        private final PasswordEncoder passwordEncoder;
        private final AuthUtil authUtil;

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

        public User signUpInternal(LoginRequestDto signupRequestDto, AuthProviderType authProviderType,
                        String providerId) {
                User user = userRepository.findByUsername(signupRequestDto.getUsername()).orElse(null);

                if (user != null)
                        throw new IllegalArgumentException("User already exists");

                user = User.builder()
                                .username(signupRequestDto.getUsername())
                                .providerId(providerId)
                                .providerType(authProviderType)
                                .build();

                if (authProviderType == AuthProviderType.EMAIL) {
                        user.setPassword(passwordEncoder.encode(signupRequestDto.getPassword()));
                }
                return userRepository.save(user);
        }

        // sign up controller
        public SignupResponseDto signup(LoginRequestDto SignupRequestDto) {
                User user = signUpInternal(SignupRequestDto, AuthProviderType.EMAIL, null);
                return new SignupResponseDto(user.getId(), user.getUsername());
        }

        @Transactional
        public ResponseEntity<LoginResponseDto> handleOAuth2LoginRequest(OAuth2User oAuth2User, String registrationId) {

                // fetch providerType and providerId
                AuthProviderType providerType = authUtil.getProviderTypeFromRegistrationId(registrationId);
                String providerId = authUtil.determineProviderIdFromOAuth2User(oAuth2User, registrationId);

                // save the providerType and porviderId info with user (prevent duplicate user
                // with different provider type)
                User user = userRepository.findByProviderIdAndProviderType(providerId, providerType).orElse(null);
                String email = oAuth2User.getAttribute("email");
                User emailUser = userRepository.findByUsername(email).orElse(null);

                if (user == null && emailUser == null) {
                        // sign up
                        String username = authUtil.determineUsernameFromOAuth2User(oAuth2User, registrationId,
                                        providerId);
                        user = signUpInternal(new LoginRequestDto(username, null), providerType, providerId);
                } else if (user != null) {
                        if (email != null && !email.isBlank() && !email.equals(user.getUsername())) {
                                user.setUsername(email);
                                userRepository.save(user);
                        }
                } else {
                        throw new BadCredentialsException("This email is already registered with provider "
                                        + emailUser.getProviderType());
                }
                // if the user has an account : directly login
                // otherwise , first signup and then login

                LoginResponseDto loginResponseDto = new LoginResponseDto(jwtService.generateToken(user), user.getId());
                return ResponseEntity.ok(loginResponseDto);
        }
}
