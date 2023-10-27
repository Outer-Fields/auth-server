package io.mindspice.authenticationserver.data.incoming;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mindspice.authenticationserver.util.Crypto;


public record PassReset (
    String username,
    String password,
    String offer,
    String captcha
) {

    public PassReset {
        username = username.toLowerCase();
        password = Crypto.genPassHash(password);
    }
}

