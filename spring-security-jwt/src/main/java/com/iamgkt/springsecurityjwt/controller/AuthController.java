package com.iamgkt.springsecurityjwt.controller;

import com.iamgkt.springsecurityjwt.dto.JwtRequest;
import com.iamgkt.springsecurityjwt.dto.JwtResponse;
import com.iamgkt.springsecurityjwt.util.JwtHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@Slf4j
@RequiredArgsConstructor
public class AuthController {

  private final UserDetailsService userDetailsService;

  private final AuthenticationManager manager;

  private final JwtHelper helper;

  @PostMapping("/login")
  public ResponseEntity<JwtResponse> login(@RequestBody JwtRequest request) {

    doAuthenticate(request.getEmail(), request.getPassword());

    UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
    String token = this.helper.generateToken(userDetails);

    JwtResponse response =
        JwtResponse.builder().jwtToken(token).username(userDetails.getUsername()).build();
    return new ResponseEntity<>(response, HttpStatus.OK);
  }

  private void doAuthenticate(String email, String password) {

    UsernamePasswordAuthenticationToken authentication =
        new UsernamePasswordAuthenticationToken(email, password);
    try {
      manager.authenticate(authentication);
    } catch (BadCredentialsException e) {
      throw new BadCredentialsException(" Invalid Username or Password  !!");
    }
  }

  @ExceptionHandler(BadCredentialsException.class)
  public String exceptionHandler() {
    return "Credentials Invalid !!";
  }
}
