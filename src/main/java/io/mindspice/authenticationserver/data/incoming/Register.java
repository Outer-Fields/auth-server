package io.mindspice.authenticationserver.data.incoming;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.mindspice.authenticationserver.util.Crypto;


public record Register(
        String username,
        @JsonProperty("display_name") String displayName,
        @JsonProperty("terms_accepted") boolean termsAccepted,
        @JsonProperty("terms_hash") String termsHash,
        String password,
        String offer,
        String captcha
) {
    public Register {
        username = username.toLowerCase();
        password = Crypto.genPassHash(password);
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("Register: ");
        sb.append("\n  username: \"").append(username).append('\"');
        sb.append(",\n  displayName: \"").append(displayName).append('\"');
        sb.append(",\n  termsAccepted: ").append(termsAccepted);
        sb.append(",\n  termsHash: \"").append(termsHash).append('\"');
        sb.append(",\n  offer: \"").append(offer).append('\"');
        sb.append(",\n  captcha: \"").append(captcha).append('\"');
        sb.append("\n");
        return sb.toString();
    }
}
