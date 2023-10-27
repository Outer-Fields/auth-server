package io.mindspice.authenticationserver.data;

public record ConfirmInfo(
        boolean success,
        String accountLauncher
) {
}
