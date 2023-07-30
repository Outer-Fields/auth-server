package io.mindspice.authenticationserver.data.incoming;

import io.mindspice.authenticationserver.util.Crypto;

public record Auth(
        String username,
        String password,
        String captcha

) {

}
