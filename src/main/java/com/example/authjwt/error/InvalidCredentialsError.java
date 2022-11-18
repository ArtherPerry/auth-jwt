package com.example.authjwt.error;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class InvalidCredentialsError extends ResponseStatusException {

    public InvalidCredentialsError() {
        super(HttpStatus.BAD_REQUEST, "Invalid Credentials!");
    }
}
