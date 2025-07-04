package com.berkai.security.spring_security_in_memory.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/private")
public class PrivateController {

    @GetMapping
    public String helloWorldPrivate(){
        return "Hello World! from private endpoint";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String helloWorldUserPrivate(){
        return "Hello World! from user private endpoint";
    }

//    @PreAuthorize("hasRole('ADMIN')") // SecurityFilterChain'de de 'role' kontrolu yapilabilir.
    @GetMapping("/admin")
    public String helloWorldAdminPrivate(){
        return "Hello World! from admin private endpoint";
    }

}
