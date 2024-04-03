package com.example.securitycourse.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/member")
public class MemberController {

    // PERMISSION MEMBER READ
    @GetMapping("")
    public String greeting() {
        return "Member Resource";
    }

}