package com.example.securitycourse.securityconfig;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/public/**").permitAll()
//                        .requestMatchers("/member/**").hasAnyRole("MEMBER", "ADMIN")
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .addFilterBefore(new ApiKeyAuthFilter(), BasicAuthenticationFilter.class)
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public UserDetailsService userDetailsService () {

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        CustomUserDetail user = new CustomUserDetail("member", encoder.encode("password"));
        user.setRoles(List.of("MEMBER"));
        user.setPermission(List.of("MEMBER_READ"));

        CustomUserDetail admin = new CustomUserDetail("admin", encoder.encode("password"));
        admin.setRoles(List.of("ADMIN"));

//        // PERFORM QUERY USER AND PASSWORD FROM DATABASE (BELOW IS MOCKUP)
//        UserDetails user = User.withUsername("member")
//                .password(encoder.encode("password"))
//                .roles("MEMBER") // Spring will store "ROLE_MEMBER"
//                .authorities("MEMBER_READ")
//                .build();
//
//        UserDetails admin = User.withUsername("admin")
//                .password(encoder.encode("password"))
//                .roles("ADMIN") // Spring will store "ROLE_ADMIN
//                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }
}