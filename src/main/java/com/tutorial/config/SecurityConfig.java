package com.tutorial.config;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.tutorial.filter.AuthFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	AuthFilter authFilter;
	
	@Override
	public void configure(HttpSecurity http) throws Exception {
        http
        .authorizeRequests()
        .antMatchers("/authenticate/**").permitAll()
        .requestMatchers(toH2Console()).permitAll()
        .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
        .anyRequest().authenticated()
        .and()
        .csrf().disable()
        .formLogin().disable()
        .sessionManagement((session) ->  session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
        .headers(header -> header.frameOptions(config -> config.sameOrigin()));
	}
	
    @Bean
    public WebSecurityCustomizer apiStaticResources() {
        return (web) -> web.ignoring()
        		.requestMatchers(PathRequest.toStaticResources().atCommonLocations())
        		.and().ignoring()
        		.antMatchers("/*.html"); 
    }
}
