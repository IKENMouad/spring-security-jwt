package com.example.demo.service.impl;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.config.security.jwt.JwtUtils;
import com.example.demo.models.User;
import com.example.demo.repository.UserRepository;
import com.example.demo.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.SneakyThrows;

@Service
public class UserServiceImpl implements UserService {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtUtils jwtUtils;

	@Override
	public List<User> fetchUsers() {
		return userRepository.findAll();
	}

	@Override
	public User createUser(User user) {

		String hashedPass = passwordEncoder.encode(user.getPassword());
		user.setPassword(hashedPass);

		if (user.getRole() == null) {
			user.setRole("USER");
		}

		user = userRepository.save(user);
		if (user != null) {
			user.setPassword("");
			return user;
		} else {
			return null;
		}
	}

	@SneakyThrows
	@Override
	public String login(User user) {
		Map<String, Object> mapObjects = new HashMap<String, Object>();
		try {
			Authentication authentication = authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword()));
			SecurityContextHolder.getContext().setAuthentication(authentication);
			String jwt = jwtUtils.generateJwtToken(authentication);

			UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

			User userToSend = new User();
			userToSend.setId(userDetails.getId());
			user.setEmail(userDetails.getEmail());

			mapObjects.put("token", jwt);
			mapObjects.put("user", user);
			String response = new ObjectMapper().writeValueAsString(mapObjects);
			return response;
		} catch (Exception e) {
			if (e instanceof BadCredentialsException) {
				throw new RuntimeException("Error: Bad Credentials " + e.getMessage());
			} else {
				throw new RuntimeException("Error: " + e.getMessage());
			}
		}
	}

}
