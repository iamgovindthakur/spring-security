package com.iamgkt.springsecurityjwt.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class HomeController {

  @RequestMapping("/test")
  public String test() {
    log.warn("This is working message");
    return "Testing message";
  }
}
