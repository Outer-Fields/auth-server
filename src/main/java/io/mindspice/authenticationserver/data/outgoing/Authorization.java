package io.mindspice.authenticationserver.data.outgoing;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.HttpStatus;


public record Authorization(
        HttpStatus httpStatus,
        String msg,
        @JsonProperty("player_id")int playerId,
        String token,
        @JsonProperty("auth_token") String authToken
) {

    public Authorization(HttpStatus httpStatus, String msg) {
        this(httpStatus, msg, -1, "", "");
    }
    public Authorization(int playerId, String token, String authToken) {
        this(HttpStatus.OK, "", playerId, token, authToken);
    }
}
