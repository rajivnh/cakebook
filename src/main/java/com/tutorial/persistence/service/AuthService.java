package com.tutorial.persistence.service;

import java.sql.SQLException;

import com.tutorial.model.AuthResponse;

public interface AuthService {
	AuthResponse findByEmailId(String emailId, String password) throws SQLException;
}
