package io.mindspice.authenticationserver.data;

import java.time.Instant;


public  class Attempt {
    int attempts;
    long lastAttempt;
    int maxAttempts = 5;
    int timeoutSec = 1200;

    public Attempt() {
        this.attempts = 1;
        this.lastAttempt = Instant.now().getEpochSecond();
    }

    public boolean isTimedOut() {
        return attempts >= maxAttempts && !isRolledOff();
    }

    public void addAttempt() {
        if (attempts >= maxAttempts) return;
        ++attempts;
        lastAttempt = Instant.now().getEpochSecond();
    }

    public boolean isRolledOff() {
        return (lastAttempt + timeoutSec) < Instant.now().getEpochSecond();
    }
}
