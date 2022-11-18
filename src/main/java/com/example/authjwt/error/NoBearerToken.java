package com.example.authjwt.error;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class NoBearerToken extends ResponseStatusException {

    public NoBearerToken(){
        super(HttpStatus.BAD_REQUEST,"No Bearer Token!");
    }
}
