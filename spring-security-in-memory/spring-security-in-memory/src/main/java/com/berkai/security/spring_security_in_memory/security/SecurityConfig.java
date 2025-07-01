package com.berkai.security.spring_security_in_memory.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;

@Configuration
@EnableMethodSecurity
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService users(){
        UserDetails user = User.builder()
                .username("brain")
                .password(passwordEncoder().encode("1234"))
                .roles("USER")
                .build();
        UserDetails admin = User.builder()
                .username("berkai")
                .password(passwordEncoder().encode("1234"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user,admin);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
      return httpSecurity
                .headers(headers ->
                        headers
                                .addHeaderWriter(new XFrameOptionsHeaderWriter(
                                        XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN
                                )))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(request -> request.requestMatchers("/public/**","/auth/**").permitAll())
              .authorizeHttpRequests(request -> request.requestMatchers("/private/admin/**").hasRole("ADMIN"))
                .authorizeHttpRequests(request -> request.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .build();

    }


}
