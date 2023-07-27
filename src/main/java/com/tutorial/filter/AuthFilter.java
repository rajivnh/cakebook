package com.tutorial.filter;

import java.io.IOException;
import java.sql.SQLException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.tutorial.jwt.JwtService;
import com.tutorial.jwt.JwtStore;
import com.tutorial.persistence.model.FakeBookUser;
import com.tutorial.persistence.service.FakeBookUserService;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AuthFilter extends OncePerRequestFilter {
	@Autowired
	JwtService jwtService;
	
	@Autowired
	FakeBookUserService fakeBookUserService;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		final String authHeader = request.getHeader("Authorization");
		
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			
			return;
		}
		
		final String accessToken = authHeader.substring(7);
		final String emailId = jwtService.extractUsername(accessToken);
		
		if(!JwtStore.validate(emailId, accessToken)) {
			filterChain.doFilter(request, response);
			
			return;
		}
		
		FakeBookUser userDetails = null;
		
		try {
			userDetails = fakeBookUserService.findByEmailId(emailId);
		} catch (SQLException e) {
			e.printStackTrace();
		}
		
		if(userDetails == null) {
			filterChain.doFilter(request, response);
			
			return;
		}
			
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
            
        filterChain.doFilter(request, response);
	}
}
