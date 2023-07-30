package io.mindspice.authenticationserver.service;

import io.mindspice.authenticationserver.data.Attempt;
import io.mindspice.authenticationserver.data.TokenInfo;
import io.mindspice.authenticationserver.data.incoming.Auth;
import io.mindspice.authenticationserver.data.incoming.Register;
import io.mindspice.authenticationserver.data.outgoing.Authorization;
import io.mindspice.authenticationserver.data.outgoing.ReturnCode;
import io.mindspice.authenticationserver.http.HttpClient;
import io.mindspice.authenticationserver.settings.AuthConfig;
import io.mindspice.authenticationserver.util.Crypto;
import io.mindspice.authenticationserver.util.ProfanityCheck;
import io.mindspice.databaseservice.client.api.OkraAuthAPI;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import io.mindspice.mindlib.data.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;


public class AuthService {

    private final ConcurrentHashMap<String, Attempt> attemptTable = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, TokenInfo> tokenTable = new ConcurrentHashMap<>();
    private final ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor();
    private final OkraAuthAPI authAPI;
    private final ProfanityCheck profanityCheck;
    private final HttpClient itemClient;

    private static final Logger mainLogger = LoggerFactory.getLogger(Authorization.class);
    private static final Logger abuseLogger = LoggerFactory.getLogger("abuseLogger");

    public AuthService(OkraAuthAPI authAPI, ProfanityCheck profanityCheck, HttpClient itemClient) {
        this.authAPI = authAPI;
        this.profanityCheck = profanityCheck;
        this.itemClient = itemClient;
    }

    public void init() {
        Runnable timeoutCleanUp = () -> {
            Set<String> keysToRemove = attemptTable.entrySet().stream()
                    .filter(entry -> entry.getValue().isRolledOff())
                    .map(Map.Entry::getKey)
                    .collect(Collectors.toSet());
            keysToRemove.forEach(attemptTable::remove);
        };
        exec.scheduleAtFixedRate(timeoutCleanUp, 0, 60, TimeUnit.SECONDS);

        Runnable tokenTimeout = () -> {
            Set<String> keysToRemove = tokenTable.entrySet().stream()
                    .filter(entry -> Instant.now().getEpochSecond() - entry.getValue().authTime() > AuthConfig.get().tokenTimeout)
                    .map(Map.Entry::getKey)
                    .collect(Collectors.toSet());
            keysToRemove.forEach(tokenTable::remove);
        };
        exec.scheduleAtFixedRate(tokenTimeout, 30, 60, TimeUnit.SECONDS);

    }

    public int getIdForToken(String token) {
        TokenInfo t = tokenTable.get(token);
        return t == null ? -1 : t.playerId();
    }

    public Authorization authenticate(Auth auth) {

        if (auth == null || auth.username() == null || auth.password() == null) {
            mainLogger.debug("Authentication contained null value");
            return new Authorization(HttpStatus.BAD_REQUEST, "Empty data fields.");
        }

        if (!isValidAttempt(auth.username())) {
            abuseLogger.info("User: " + auth.username() + " exceeded invalid login count, timed out");
            return new Authorization(HttpStatus.FORBIDDEN, "Too many logins attempts, 10 minute cool down.");
        }

        var cred = authAPI.getUserCredentials(auth.username());
        if (!cred.success() || cred.data().isEmpty()) {
            mainLogger.debug("User: " + auth.username() + " does not exist");
            abuseLogger.info("User: " + auth.username() + " does not exist");
            return new Authorization(HttpStatus.UNAUTHORIZED, "Invalid Login.");
        }

        if (Crypto.comparePassHash(cred.data().get().passHash(), auth.password())) {
            String token = Crypto.getToken();
            tokenTable.put(token, new TokenInfo(cred.data().get().playerId()));
            mainLogger.info("User: " + auth.username() + " authenticated");
            authAPI.updateLastLogin(cred.data().get().playerId());
            return new Authorization(cred.data().get().playerId(), token);
        }

        addInvalidAttempt(auth.username());
        abuseLogger.info("User: " + auth.username() + " failed login attempt");
        return new Authorization(HttpStatus.UNAUTHORIZED, "Invalid Login.");
    }

    public Pair<HttpStatus, String> register(Register reg) {
        if (reg == null) { new Pair<>(HttpStatus.BAD_REQUEST, "Empty data fields."); }
        if (reg.username().isEmpty()) {new Pair<>(HttpStatus.BAD_REQUEST, "Empty data fields."); }
        if (reg.password().isEmpty()) {new Pair<>(HttpStatus.BAD_REQUEST, "Empty data fields."); }
        if (!reg.isAddressCorrect()) { new Pair<>(HttpStatus.BAD_REQUEST, "Invalid Address."); }
        if (!reg.isPwCorrect()) { new Pair<>(HttpStatus.BAD_REQUEST, "Invalid password, should be sha256 hash, DEBUG, client shouldn't get this error."); }

        if (authAPI.userExists(reg.username()).data().orElse(true)) {
            mainLogger.info("User: " + reg.username() + " | " + reg.displayName() +
                                    " not registered, user already exists");
            return new Pair<>(HttpStatus.CONFLICT, "Username already exists.");
        }

        if (reg.username().length() > 15 || reg.username().contains(" ")
                || reg.displayName().length() > 15 || reg.displayName().contains(" ")) {
            mainLogger.info("User: " + reg.username() + " | " + reg.displayName() +
                                    " not registered, invalid user/display name, user/display name must be " +
                                    "<=15 characters and not contain spaces.");
            return new Pair<>(HttpStatus.BAD_REQUEST, "User and display name should not contain more than 15 characters");
        }
        if (profanityCheck.profanityCheck(reg.displayName())) {
            mainLogger.info("User: " + reg.username() + " | " + reg.displayName() +
                                    " not registered, profane display name");
            return new Pair<>(HttpStatus.BAD_REQUEST, "Display name should not contain profanity");
        }

        int playerId = authAPI.registerUser(reg.username(), reg.displayName(), reg.password())
                .data().orElse(-1);

        if (playerId == -1) {
            mainLogger.error("User: " + reg.username() + " | " + reg.displayName() +
                                    " failed to fetch player id, this should not happen");
            return new Pair<>(HttpStatus.BAD_REQUEST, "DEBUG: player id failed to lookup, if you see this report as a bug");
        }
        itemClient.mintAccountNft(playerId, reg.address());
        mainLogger.info("User: " + reg.username() + " | " + reg.displayName() +
                                 " registered");
        return new Pair<>(HttpStatus.OK, "Account Registered Successfully");
    }

    private boolean isValidAttempt(String username) {
        if (!attemptTable.containsKey(username)) return true;
        if (!attemptTable.get(username).isTimedOut()) {
            if (attemptTable.get(username).isRolledOff()) {
                attemptTable.remove(username);
            }
            return true;
        } else {
            return false;
        }
    }

    private void addInvalidAttempt(String username) {
        var lookup = attemptTable.get(username);

        if (lookup == null) {
            attemptTable.put(username, new Attempt());
        } else {
            lookup.addAttempt();
        }
    }
}
