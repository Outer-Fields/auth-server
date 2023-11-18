package io.mindspice.authenticationserver.data.incoming;

import io.mindspice.authenticationserver.util.Crypto;


public record Auth(
        String username,
        String password,
        String captcha

) {
    public Auth {
        username = username.toLowerCase();
    }
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("Auth: ");
        sb.append("\n  username: \"").append(username).append('\"');
        sb.append(",\n  captcha: \"").append(captcha).append('\"');
        sb.append("\n");
        return sb.toString();
    }
}
