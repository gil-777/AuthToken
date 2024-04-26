package com.demojwt.Auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.demojwt.jwt.JwtService;
import com.demojwt.user.Role;
import com.demojwt.user.User;
import com.demojwt.user.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
	private final UserRepository userRepository;
	private final JwtService jwtService;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
	
	public AuthResponse login(LoginRequest request) {//52.37
		System.out.println("username: "+request.getUsername()+" password= "+request.getPassword());
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
		System.out.println("herere 00 ****");
		UserDetails user=userRepository.findByUsername(request.getUsername()).orElseThrow();
		System.out.println("herere 001****");
		String token=jwtService.getToken(user);
		return AuthResponse.builder()
				.token(token)
				.build()
				;
	}

	public AuthResponse register(RegisterRequest request) {
		User user = User.builder()
				.username(request.getUsername())
				.password(passwordEncoder.encode(request.getPassword()))
				.firstname(request.getFirstname())
				.lastname(request.getLastname())
				.country(request.getCountry())
				.role(Role.USER)
				.build();
		System.out.println("GUARDANDO*");
		System.out.println("request");
		System.out.println("name: "+request.getFirstname());
		System.out.println("last name "+request.getLastname());
		System.out.println("username "+request.getUsername());
		System.out.println("password: "+request.getPassword());
		System.out.println("country: "+request.getCountry());
		System.out.println(user);
		try {
			userRepository.save(user);
		} catch (Exception e) {
			System.out.println("here excep");
			e.printStackTrace();
		}
		
		return AuthResponse.builder()
				.token(jwtService.getToken(user))
				.build();
	}

}
