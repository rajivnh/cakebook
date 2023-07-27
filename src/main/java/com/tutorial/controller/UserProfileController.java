package com.tutorial.controller;

import java.sql.SQLException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tutorial.persistence.model.FakeBookUser;
import com.tutorial.persistence.service.FakeBookUserService;

@RestController
public class UserProfileController {
	@Autowired
	FakeBookUserService fakeBookUserService;
	
	@PreAuthorize("hasAuthority('ROLE_USER')")
	@PostMapping("/user/profile")
	public ResponseEntity<FakeBookUser> findByEmailId() throws SQLException {
		String emailId = ((UserDetails)SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername();
		
		var userDetails = fakeBookUserService.findByEmailId(emailId);
		
		userDetails.setPassword(null);
		
		return new ResponseEntity<>(userDetails, HttpStatus.OK);
	}
}
