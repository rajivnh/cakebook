package com.tutorial.jwt;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class JwtStore {
	private static Map<String, String> TOKEN_STORE = new ConcurrentHashMap<String, String>();
	
	public static void add(String emailId, String token) {
		TOKEN_STORE.put(emailId, token);
	}
	
	public static void remove(String emailId) {
		TOKEN_STORE.remove(emailId);
	}
	
	public static boolean validate(String emailId, String accessToken) {
		if(!TOKEN_STORE.containsKey(emailId)) {
			return false;
		}
		
		return TOKEN_STORE.get(emailId).equals(accessToken) ? true : false;
	}
}
