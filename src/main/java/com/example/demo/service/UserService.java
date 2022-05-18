package com.example.demo.service;

import java.util.List;

import com.example.demo.models.User;

public interface UserService {
	List<User> fetchUsers();

	User createUser(User user);

	String login(User user);
}
