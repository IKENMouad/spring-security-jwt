package com.example.demo.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.models.User;
import com.example.demo.service.UserService;
import com.example.demo.service.impl.UserDetailsImpl;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.SneakyThrows;

@RestController
@CrossOrigin("*")
@RequestMapping("/api/auth")
public class AuthController {

	@Autowired
	private UserService userService;

	@GetMapping("/users")
	@SneakyThrows
	public ResponseEntity<?> fetchUsers() {

		List<User> users = userService.fetchUsers();

		UserDetailsImpl detailsImpl = (UserDetailsImpl) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		String username = "anonymosUser";
		if (detailsImpl != null) {
			username = detailsImpl.getUsername();
		}

		Map<String, Object> maps = new HashMap<>();

		maps.put("users", users);
		maps.put("username", username);

		String response = new ObjectMapper().writeValueAsString(maps);
		return new ResponseEntity<>(response, HttpStatus.OK);
	}

	@PostMapping("/signup")
	public User signup(@RequestBody User user) {
		return userService.createUser(user);
	}

	@PostMapping(value = "/signin", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
	@SneakyThrows
	public ResponseEntity<String> authenticateUser(@RequestBody User user) {
		String response = userService.login(user);
		return ResponseEntity.ok(response);
	}
}
