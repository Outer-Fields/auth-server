package io.mindspice.authenticationserver.service;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import io.mindspice.authenticationserver.data.Attempt;
import io.mindspice.authenticationserver.data.incoming.Auth;
import io.mindspice.authenticationserver.data.incoming.PassReset;
import io.mindspice.authenticationserver.data.incoming.Register;
import io.mindspice.authenticationserver.data.outgoing.Authorization;
import io.mindspice.authenticationserver.settings.AuthConfig;
import io.mindspice.authenticationserver.util.Crypto;
import io.mindspice.authenticationserver.util.Log;
import io.mindspice.authenticationserver.util.ProfanityCheck;
import io.mindspice.databaseservice.client.api.OkraAuthAPI;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import io.mindspice.databaseservice.client.util.Util;
import io.mindspice.jxch.rpc.http.WalletAPI;
import io.mindspice.jxch.rpc.schemas.wallet.offers.OfferSummary;
import io.mindspice.jxch.rpc.util.bech32.AddressUtil;
import io.mindspice.mindlib.data.Pair;
import org.springframework.http.HttpStatus;


public class AuthService {

    private final Map<String, Attempt> attemptTable = new ConcurrentHashMap<>();
    private final Map<String, Pair<Integer, Long>> tokenTable = new ConcurrentHashMap<>();
    private final Map<String, Pair<String, Long>> sessionTable = new ConcurrentHashMap<>();
    private final Map<String, Pair<Integer, Long>> tempAuthTokens = new ConcurrentHashMap<>();

    private final OkraAuthAPI authAPI;
    private final ProfanityCheck profanityCheck;
    private final WalletAPI walletAPI;

    private final ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor();

    private static final Log mainLogger = Log.SERVER;
    private static final Log abuseLogger = Log.ABUSE;

    public AuthService(OkraAuthAPI authAPI, ProfanityCheck profanityCheck, WalletAPI walletAPI) {
        this.authAPI = authAPI;
        this.profanityCheck = profanityCheck;
        this.walletAPI = walletAPI;
    }

    public void init() {
        Runnable timeoutCleanUp = () -> {
            Set<String> attemptRemovals = attemptTable.entrySet().stream()
                    .filter(entry -> entry.getValue().isRolledOff())
                    .map(Map.Entry::getKey)
                    .collect(Collectors.toSet());

            Set<String> tokenRemovals = tokenTable.entrySet().stream()
                    .filter(entry -> Instant.now().getEpochSecond() - entry.getValue().second() > AuthConfig.get().tokenTimeout)
                    .map(Map.Entry::getKey)
                    .collect(Collectors.toSet());

            Set<String> sessionRemovals = sessionTable.entrySet().stream()
                    .filter(entry -> Instant.now().getEpochSecond() - entry.getValue().second() > 60 * 10)
                    .map(Map.Entry::getKey)
                    .collect(Collectors.toSet());

            Set<String> tempAuthRemovals = tempAuthTokens.entrySet().stream()
                    .filter(entry -> Instant.now().getEpochSecond() - entry.getValue().second() > 60)
                    .map(Map.Entry::getKey)
                    .collect(Collectors.toSet());

            attemptRemovals.forEach(attemptTable::remove);
            tokenRemovals.forEach(tokenTable::remove);
            sessionRemovals.forEach(sessionTable::remove);
            tempAuthRemovals.forEach(tempAuthTokens::remove);
        };
        exec.scheduleAtFixedRate(timeoutCleanUp, 0, 60, TimeUnit.SECONDS);
        mainLogger.info("Started AuthService");

    }

    public Map<String, Pair<String, Long>> getSessionTable() {
        return sessionTable;
    }

    public String newTempAuth(int playerId) {
        String authToken = Crypto.getToken();
        tempAuthTokens.put(authToken, new Pair<>(playerId, Instant.now().getEpochSecond()));
        return authToken;
    }

    public int validateTempAuth(String token) {
        Pair<Integer, Long> t = tempAuthTokens.get(token);
        tempAuthTokens.remove(token);
        return t == null ? -1 : t.first();
    }

    public int getIdForToken(String token) {
        Pair<Integer, Long> t = tokenTable.get(token);
        return t == null ? -1 : t.first();
    }

    public Authorization authenticate(String originIp, Auth auth) {

        if (auth == null || auth.username() == null || auth.password() == null) {
            mainLogger.debug(this.getClass(), "Authentication contained null value");
            return new Authorization(HttpStatus.BAD_REQUEST, "Empty data fields.");
        }

        if (!isValidAttempt(auth.username())) {
            abuseLogger.info("Login Timeout | + OriginIP: " + originIp + " | User: " + auth.username());
            return new Authorization(HttpStatus.FORBIDDEN, "Too many logins attempts, 10 minute cool down.");
        }

        var cred = authAPI.getUserCredentials(auth.username());
        if (!cred.success() || cred.data().isEmpty()) {
            mainLogger.debug(this.getClass(), "User: " + auth.username() + " does not exist");
            abuseLogger.info("Nonexistent Username | OriginIP: " + originIp + " | User: " + auth.username());
            return new Authorization(HttpStatus.UNAUTHORIZED, "Invalid Login.");
        }
        if (Crypto.comparePassHash(cred.data().get().passHash(), auth.password())) {
            String token = Crypto.getToken();
            String authToken = Crypto.getToken();
            long now = Instant.now().getEpochSecond();
            int playerId = cred.data().get().playerId();
            tokenTable.put(token, new Pair<>(playerId, now));
            tempAuthTokens.put(authToken, new Pair<>(playerId, now));
            mainLogger.info("User: " + auth.username() + " authenticated");
            authAPI.updateLastLogin(playerId);
            return new Authorization(playerId, token, authToken);
        }

        addInvalidAttempt(auth.username());
        abuseLogger.info("Failed login | OriginIP: " + originIp + " | User: " + auth.username());
        return new Authorization(HttpStatus.UNAUTHORIZED, "Invalid Login.");
    }

    public Pair<HttpStatus, String> register(String originIp, Register reg) {

        if (reg == null) { return new Pair<>(HttpStatus.BAD_REQUEST, "Empty data fields."); }
        if (reg.username().isEmpty()) { return new Pair<>(HttpStatus.BAD_REQUEST, "Empty username field."); }
        if (reg.password().isEmpty()) { return new Pair<>(HttpStatus.BAD_REQUEST, "Empty password field."); }
        if (reg.displayName().isEmpty()) { return new Pair<>(HttpStatus.BAD_REQUEST, "Empty display name field."); }
        if (reg.offer().isEmpty()) { return new Pair<>(HttpStatus.BAD_REQUEST, "Empty offer field."); }
        if (!reg.termsAccepted()) {return new Pair<>(HttpStatus.BAD_REQUEST, "Must Accept terms."); }
        if (!reg.termsHash().equals("5be59c53700aab0802740a4ddd165b67bb359afa6ff41313a05ad32b2458c012")) {
            return new Pair<>(HttpStatus.BAD_REQUEST, "Invalid terms hash");
        }

        if (authAPI.userExists(reg.username()).data().orElseThrow()) {
            mainLogger.info("User: " + reg.username() + " | " + reg.displayName() +
                    " not registered, user already exists");
            return new Pair<>(HttpStatus.CONFLICT, "Username already exists.");
        }

        if (reg.username().length() > 15 || reg.username().contains(" ")
                || reg.displayName().length() > 15 || reg.displayName().contains(" ")) {
            mainLogger.info("User: " + reg.username() + " | " + reg.displayName() +
                    " not registered, invalid user/display name");
            return new Pair<>(HttpStatus.BAD_REQUEST, "User and display name should not contain more than 15 characters");
        }

        if (profanityCheck.profanityCheck(reg.displayName())) {
            mainLogger.info("User: " + reg.username() + " | " + reg.displayName() +
                    " not registered, profane display name");
            return new Pair<>(HttpStatus.BAD_REQUEST, "Display name should not contain profanity");
        }
        String finalName = reg.displayName();
        while (authAPI.userExists(finalName).data().orElseThrow()) {
            finalName = reg.displayName() + ThreadLocalRandom.current().nextInt(0, 999);
        }

        Pair<Boolean, String> offerValidation = validateOffer(reg.username(), reg.offer(), true);
        if (!offerValidation.first()) {
            return new Pair<>(HttpStatus.BAD_REQUEST, offerValidation.second());
        }

        int playerId = authAPI.registerUser(finalName, reg.displayName(), reg.password(),
                reg.termsAccepted(), reg.termsHash()).data().orElse(-1);

        if (playerId == -1) {
            mainLogger.error(this.getClass(), "User: " + reg.username() + " | " + finalName +
                    " failed to fetch player id, this should not happen");
            return new Pair<>(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error, please report");
        }

        authAPI.updatePlayerDid(playerId, offerValidation.second());
        mainLogger.info("User: " + reg.username() + " | " + reg.displayName() + "registered, with account NFT:" + offerValidation.second());

        return new Pair<>(HttpStatus.OK, "Registration Successful!");
    }

    public Pair<HttpStatus, String> resetPassword(String originIp, PassReset resetInfo) {
        if (resetInfo == null) { return new Pair<>(HttpStatus.BAD_REQUEST, "Empty data fields."); }
        if (resetInfo.username().isEmpty()) { return new Pair<>(HttpStatus.BAD_REQUEST, "Empty username fields."); }
        if (resetInfo.password().isEmpty()) { return new Pair<>(HttpStatus.BAD_REQUEST, "Empty password fields."); }
        if (resetInfo.offer().isEmpty()) { return new Pair<>(HttpStatus.BAD_REQUEST, "Empty offer field."); }

        if (!authAPI.userExists(resetInfo.username()).data().orElseThrow()) {
            abuseLogger.info("Invalid Reset Username | OriginIP: " + originIp + " | Username+ " + resetInfo.username());
            return (new Pair<>(HttpStatus.BAD_REQUEST, "Bad Request"));
        }

        var credentials = authAPI.getUserCredentials(resetInfo.username());
        if (!credentials.success() || credentials.data().isEmpty()) {
            mainLogger.info("Failed to get credentials for password reset player: " + resetInfo.username());
            return (new Pair<>(HttpStatus.BAD_REQUEST, "Bad Request"));
        }
        var playerId = credentials.data().get().playerId();

        long lastReset = authAPI.getLastPasswordReset(playerId).data().orElseThrow();
        if (Instant.now().getEpochSecond() - lastReset < 3600) {
            return (new Pair<>(HttpStatus.FORBIDDEN, "Can only reset once per hour"));
        }

        var playersLauncher = authAPI.getPlayerAccountLauncher(playerId);
        if (!playersLauncher.success() || playersLauncher.data().isEmpty()) {
            mainLogger.error(this.getClass(), "Failed to get account launcher for password reset |  Player: "
                    + resetInfo.username());
            return (new Pair<>(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error"));
        }

        Pair<Boolean, String> offerValidation = validateOffer(resetInfo.username(), resetInfo.offer(), false);

        if (!offerValidation.first()) {
            return new Pair<>(HttpStatus.BAD_REQUEST, offerValidation.second());
        }

        if (playersLauncher.data().get().equals(Util.normalizeHex(offerValidation.second()))) {
            authAPI.updatePlayerPassword(playerId, resetInfo.password());
            return new Pair<>(HttpStatus.OK, "Password successful reset");
        } else {
            abuseLogger.info("Invalid Reset Offer | OriginIP:  " + originIp + " | PlayerId: " + playerId
                    + " | Launcher Id: " + offerValidation.second());
            return new Pair<>(HttpStatus.FORBIDDEN, "Invalid launcher offered");
        }
    }

    private Pair<Boolean, String> validateOffer(String username, String offer, boolean isReg) {
        try {
            if (!walletAPI.checkOfferValidity(offer).data().orElseThrow().valid()) {
                mainLogger.info("Invalid offer submitted for username: " + username);
                return new Pair<>(false, "Invalid offer file");
            }

            OfferSummary summary = walletAPI.getOfferSummary(offer, false).data().orElseThrow();
            Map.Entry<String, Long> offered = summary.offered().entrySet().iterator().next();
            Map.Entry<String, Long> requested = summary.requested().entrySet().iterator().next();

            if (requested.getKey().equals("xch") && requested.getValue() > 100000000000L
                    && authAPI.isValidDidLauncher(offered.getKey()).data().orElseThrow()) {
                if (isReg) {
                    if (authAPI.checkForExistingLauncher(offered.getKey()).success()) {
                        return new Pair<>(false, "Offered account NFT already linked");
                    }
                    String offerDid = getDidFromInfo(summary.infos());
                    if (!offerDid.isEmpty()) {
                        var dupeCheck = authAPI.checkForDuplicateLauncher(offered.getKey(), offerDid).data().orElseThrow();
                        if (dupeCheck.isValid()) {
                            return new Pair<>(true, offered.getKey());
                        } else {
                            return new Pair<>(false, "Multiple Account NFTs under DID, please use: "
                                    + AddressUtil.encode("nft", dupeCheck.launcherId()) + " to register");
                        }
                    }
                }

                return new Pair<>(true, offered.getKey());
            } else {
                return new Pair<>(false, "Invalid Asset Offered");
            }
        } catch (Exception e) {
            mainLogger.error(this.getClass(), "Exception in validate offer", e);
            return new Pair<>(false, "Server Encounter Error: Invalid offer");
        }
    }

    private String getDidFromInfo(JsonNode info) {
        if (info == null) { return ""; }
        try {
            int i = 10;
            while (info.has("also") || info.has("owner")) {
                if (info.has("owner")) {
                    return info.get("owner").asText();
                } else {
                    info = info.get("also");
                }
            }
        } catch (Exception e) {
            return "";
        }
        return "";
    }

    private boolean isValidAttempt(String username) {
        if (!attemptTable.containsKey(username)) { return true; }
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
