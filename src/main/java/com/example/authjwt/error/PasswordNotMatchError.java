package com.example.authjwt.error;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class PasswordNotMatchError extends ResponseStatusException {

    public PasswordNotMatchError() {
        super(HttpStatus.BAD_REQUEST, "Password do not match!");
    }
}
