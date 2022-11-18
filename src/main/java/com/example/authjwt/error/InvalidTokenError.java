package com.example.authjwt.error;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class InvalidTokenError extends ResponseStatusException {

    public InvalidTokenError() {
        super(HttpStatus.BAD_REQUEST,"Recovery Token Not Found!");
    }
}
