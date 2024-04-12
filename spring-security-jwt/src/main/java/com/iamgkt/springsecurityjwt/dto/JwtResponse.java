package com.iamgkt.springsecurityjwt.dto;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class JwtResponse {
  private String username;
  private String jwtToken;
}
