package com.drodionov.learning.springoauth2.web.config;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.csrf.CookieCsrfTokenRepository.withHttpOnlyFalse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@Configuration
public class WebConfig {

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(
            (auth) -> auth.requestMatchers("/", "/csrf", "/index.html", "/error", "/webjars/**")
                .permitAll()
                .anyRequest()
                .authenticated())
        .exceptionHandling(
            exception -> exception.authenticationEntryPoint(new HttpStatusEntryPoint(UNAUTHORIZED)))
        .csrf(csrfConfigurer -> csrfConfigurer.csrfTokenRepository(withHttpOnlyFalse()))
        .logout(logout -> logout.logoutSuccessUrl("/").permitAll())
        .oauth2Login(withDefaults())
        .build();
  }
}
