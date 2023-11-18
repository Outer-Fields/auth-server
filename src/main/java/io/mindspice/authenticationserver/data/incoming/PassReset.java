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

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("PassReset: ");
        sb.append("\n  username: \"").append(username).append('\"');
        sb.append(",\n  offer: \"").append(offer).append('\"');
        sb.append(",\n  captcha: \"").append(captcha).append('\"');
        sb.append("\n");
        return sb.toString();
    }
}

