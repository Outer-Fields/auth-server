package io.mindspice.authenticationserver;

import io.mindspice.authenticationserver.settings.AuthConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.IOException;


@SpringBootApplication
public class AuthenticationServerApplication {

	public static void main(String[] args) throws IOException {
		SpringApplication.run(AuthenticationServerApplication.class, args);
	}

}
