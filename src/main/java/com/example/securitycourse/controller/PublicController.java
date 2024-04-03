package com.example.securitycourse.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/greeting")
public class PublicController {

    @GetMapping("")
    public String greeting() {
        return "Public Resource";
    }

}
