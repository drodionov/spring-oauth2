package com.drodionov.learning.springoauth2.web.config;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@Configuration
public class WebSecurityConfigAdapter {

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(
            (auth) -> auth.requestMatchers("/", "/index.html", "/error", "/webjars/**").permitAll().anyRequest()
                .authenticated()
        ).exceptionHandling(
            exception -> exception.authenticationEntryPoint(new HttpStatusEntryPoint(UNAUTHORIZED)))
        .oauth2Login(withDefaults())
        .build();
  }
}
