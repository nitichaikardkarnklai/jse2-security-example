package com.example.securitycourse.service;

import com.example.securitycourse.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    public AuthenticationUserDetailService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findUserByUsername(username);
    }
}

/*
    @Bean
    public UserDetailsService userDetailsService () {

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        CustomUserDetail user = new CustomUserDetail("member", encoder.encode("password"));
        user.setRoles(List.of("MEMBER"));
        user.setPermission(List.of("MEMBER_READ"));

        CustomUserDetail admin = new CustomUserDetail("admin", encoder.encode("password"));
        admin.setRoles(List.of("ADMIN"));

        return new InMemoryUserDetailsManager(user, admin);
    }
 */