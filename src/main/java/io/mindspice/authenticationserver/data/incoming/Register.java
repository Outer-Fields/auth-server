package io.mindspice.authenticationserver.data.incoming;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mindspice.authenticationserver.util.Crypto;


public record Register(
        String username,
        @JsonProperty("display_name") String displayName,
        String password,
        String offer,
        String captcha
) {
    public Register {
        username = username.toLowerCase();
        password = Crypto.genPassHash(password);
    }


}
