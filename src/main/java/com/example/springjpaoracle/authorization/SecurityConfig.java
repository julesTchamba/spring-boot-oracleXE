package com.example.springjpaoracle.authorization;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter
{

    public static final String TEACHER = "teacher";
    public static final String STUDENT = "student";
    public static final String ADMIN = "admin";

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter()
    {
        final var jwtAuthenticationConverter = new JwtAuthenticationConverter();
        final var converter = new CustomJwtConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(converter);
        return jwtAuthenticationConverter;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception
    {
        final var STUDENT_END_P =  "/students/**";
        http.authorizeRequests()
                .mvcMatchers(HttpMethod.GET, "/courses").permitAll()
                .mvcMatchers(HttpMethod.POST, "/courses/score").hasAuthority(TEACHER)
                .mvcMatchers(HttpMethod.GET, "/courses/score/student/**").hasAnyAuthority(STUDENT, TEACHER)
                .mvcMatchers(HttpMethod.GET, "/courses/score/**").hasAuthority(TEACHER)
                .mvcMatchers(HttpMethod.POST, "/courses/assignteacher").hasAuthority(ADMIN)
                .mvcMatchers(HttpMethod.GET, STUDENT_END_P).hasAnyAuthority(ADMIN, "user")
                .mvcMatchers(HttpMethod.POST, STUDENT_END_P).hasAuthority(ADMIN)
                .mvcMatchers(HttpMethod.DELETE, STUDENT_END_P).hasAuthority(ADMIN)
                .and().cors()
                .and().oauth2ResourceServer().jwt()
                .jwtAuthenticationConverter(jwtAuthenticationConverter());
    }

    @Bean
    public ResourceOwnerOrGrantedAuthority isOwnerOrAnyAuthorities()
    {
        return new ResourceOwnerOrGrantedAuthority(() -> SecurityContextHolder.getContext().getAuthentication());
    }
}
