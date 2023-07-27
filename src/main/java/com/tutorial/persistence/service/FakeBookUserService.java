package com.tutorial.persistence.service;

import java.sql.SQLException;

import com.tutorial.persistence.model.FakeBookUser;

public interface FakeBookUserService {
	boolean isValid(String emailId, String password) throws SQLException;
	
	FakeBookUser findByEmailId(String emailId) throws SQLException;
}
