package com.lobna.security.auth;

import lombok.NoArgsConstructor;

@NoArgsConstructor
public class AuthenticationResponse {

    private String token;


    public AuthenticationResponse(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }
}
