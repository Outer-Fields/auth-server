package io.mindspice.authenticationserver.data;

import java.time.Instant;


public record TokenInfo(
        int playerId,
        long authTime
) {
    public TokenInfo(int playerId) {
        this(playerId, Instant.now().getEpochSecond());
    }
}
