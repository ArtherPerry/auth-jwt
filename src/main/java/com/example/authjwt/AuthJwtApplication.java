package com.example.authjwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jdbc.repository.config.EnableJdbcRepositories;

@SpringBootApplication
@EnableJdbcRepositories
public class AuthJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthJwtApplication.class, args);
    }

}
