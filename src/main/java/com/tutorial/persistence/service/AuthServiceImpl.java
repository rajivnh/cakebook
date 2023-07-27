package com.tutorial.persistence.service;

import java.sql.SQLException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tutorial.jwt.JwtService;
import com.tutorial.jwt.JwtStore;
import com.tutorial.model.AuthResponse;
import com.tutorial.persistence.model.FakeBookUser;

@Service
public class AuthServiceImpl implements AuthService {
	@Autowired
	FakeBookUserService fakeBookUserService;
	
	@Autowired
	JwtService jwtService;
	
	@Override
	public AuthResponse findByEmailId(String emailId, String password) throws SQLException {
		if(!fakeBookUserService.isValid(emailId, password)) {
			throw new SQLException("Invalid Password!");
		}
		
		FakeBookUser userDetails = fakeBookUserService.findByEmailId(emailId);
		
		var accessToken = jwtService.generateToken(userDetails);
	    var refreshToken = jwtService.generateRefreshToken(userDetails);
	    
	    JwtStore.add(emailId, accessToken);
	    
	    AuthResponse response = new AuthResponse();
	    
	    response.setAccessToken(accessToken);
	    response.setRefreshToken(refreshToken);
		    
		return response;
	}
}
