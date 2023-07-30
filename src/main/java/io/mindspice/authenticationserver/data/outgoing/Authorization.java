package io.mindspice.authenticationserver.data.outgoing;

import org.springframework.http.HttpStatus;


public record Authorization(
        HttpStatus httpStatus,
        String msg,
        int playerId,
        String token
) {

    public Authorization(HttpStatus httpStatus, String msg) {
        this(httpStatus, msg, -1, "");
    }
    public Authorization(int playerId, String token) {
        this(HttpStatus.OK, "", playerId, token);
    }
}
