package io.mindspice.authenticationserver.data.outgoing;

public enum ReturnCode {
    VALID,
    INVALID,
    TIMEOUT,
    PROFANE,
    INVALID_CAPTCHA,
    USER_EXISTS
}
