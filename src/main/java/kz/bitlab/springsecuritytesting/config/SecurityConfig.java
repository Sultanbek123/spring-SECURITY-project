package kz.bitlab.springsecuritytesting.config;

import kz.bitlab.springsecuritytesting.services.MyUserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    public MyUserService userService(){
        return new MyUserService();
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder
                .userDetailsService(userService())
                .passwordEncoder(passwordEncoder());

        http.exceptionHandling().accessDeniedPage("/403");

        http.formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/sign-in")
                .defaultSuccessUrl("/home")
                .failureUrl("/login?error")
                .usernameParameter("user-email")
                .passwordParameter("user-password");
        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login");

        return http.build();
    }
}
