package com.example.securitycourse.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/member")
public class MemberController {

    @PreAuthorize("hasAuthority('MEMBER_READ') or hasRole('ADMIN')")
    @GetMapping("")
    public String getMember() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        System.out.println("!!!!" +authentication);
        return "Member Resource";
    }

    @PutMapping("")
    public String editMember() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return "Edit: Member Resource";
    }

}
