package io.mindspice.authenticationserver.data.incoming;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mindspice.authenticationserver.util.Crypto;


public record Register(
        String username,
       @JsonProperty("display_name") String displayName,
        String password,
        String address,
        String captcha
) {
    public Register {
        password = Crypto.genPassHash(password);
    }

    public boolean isPwCorrect() {
        return password.length() == 64;
    }

    public boolean isAddressCorrect() {
        return address.length() == 62;
    }

}
