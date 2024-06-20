package com.wissen.springsecurity.controller;

import com.wissen.springsecurity.entity.Role;
import com.wissen.springsecurity.entity.User;
import com.wissen.springsecurity.model.AuthenticationResponse;
import com.wissen.springsecurity.model.UserRequest;
import com.wissen.springsecurity.repository.UserRepository;
import com.wissen.springsecurity.services.AuthenticationService;
import com.wissen.springsecurity.services.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@CrossOrigin
public class AuthenticationController {

    private final AuthenticationService authenticationService;


    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }


    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody UserRequest userRequest){
        userRequest.setRole(Role.USER);
        return ResponseEntity.ok(authenticationService.register(userRequest));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody UserRequest userRequest){
        return ResponseEntity.ok(authenticationService.authenticate(userRequest));
    }


}
