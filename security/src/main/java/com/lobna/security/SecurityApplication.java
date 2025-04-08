package com.lobna.security;

import com.lobna.security.auth.AuthenticationService;
import com.lobna.security.auth.RegisterRequest;
import com.lobna.security.user.Role;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(AuthenticationService authenticationService) {
		return args -> {
			var admin = RegisterRequest.builder().firstname("Admin").lastname("Admin").email("admin@mail.com").password("password").role(Role.ADMIN).build();
			System.out.println("Admin token: "+ authenticationService.register(admin).getAccessToken());

			var admin = RegisterRequest.builder().firstname("Admin").lastname("Admin").email("admin@mail.com").password("password").role(Role.ADMIN).build();
			System.out.println("Admin token: "+ authenticationService.register(admin).getAccessToken());
			var manager = RegisterRequest.builder().firstname("Manager").lastname("Manager").email("manager@mail.com").password("password").role(Role.MANAGER).build();
			System.out.println("Admin token: "+ authenticationService.register(manager).getAccessToken());

		};
	}
}
