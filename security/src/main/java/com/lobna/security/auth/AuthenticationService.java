package com.lobna.security.auth;

import com.lobna.security.config.JwtService;
import com.lobna.security.token.Token;
import com.lobna.security.token.TokenRepository;
import com.lobna.security.token.TokenType;
import com.lobna.security.user.Role;
import com.lobna.security.user.User;
import com.lobna.security.user.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final UserRepository repository;

    private final TokenRepository tokenRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserRepository repository, TokenRepository tokenRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.repository = repository;
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationResponse register(RegisterRequest request) {
        var user = new User(request.getFirstname(),request.getLastname(),request.getEmail(),passwordEncoder.encode(request.getPassword()), Role.USER);
        var savedUser = repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        saveUserToken(jwtToken, savedUser);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }

    private void saveUserToken(String jwtToken, User user) {
        var token = new Token(jwtToken, TokenType.BEARER, false, false, user);
        tokenRepository.save(token);
    }


    private void revokeAllUserTokens(User user){
    var validTokens = tokenRepository.findAllValidTokensByUser(user.getId());
    if(validTokens.isEmpty()){
        return;
    }
    validTokens.forEach(token -> {
        token.setExpired(true);
        token.setRevoked(true);
    });
    tokenRepository.saveAll(validTokens);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getEmail(), request.getPassword()
        ));
        var user = repository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(jwtToken, user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }
}
