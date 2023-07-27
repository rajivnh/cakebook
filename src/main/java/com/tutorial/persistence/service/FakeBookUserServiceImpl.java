package com.tutorial.persistence.service;

import java.sql.SQLException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.tutorial.persistence.model.FakeBookUser;
import com.tutorial.persistence.repository.FakeBookUserRepository;

@Service
public class FakeBookUserServiceImpl implements FakeBookUserService {
	@Autowired
	FakeBookUserRepository repository;
	
	@Autowired
	PasswordEncoder encoder;
	
	@Override
	public FakeBookUser findByEmailId(String emailId) throws SQLException {
		FakeBookUser userDetails = repository.findById(emailId).orElseThrow(() -> new SQLException("Email Id Not Found"));
		
		return userDetails;
	}
	
	@Override
	public boolean isValid(String emailId, String password) throws SQLException {
		FakeBookUser userDetails = repository.findById(emailId).orElseThrow(() -> new SQLException("Email Id Not Found"));
		
		return encoder.matches(password, userDetails.getPassword()) ? true : false;
	}
}
