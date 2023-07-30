package io.mindspice.authenticationserver.util;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import java.security.SecureRandom;
import java.util.Base64;


public class Crypto {
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder encoder = Base64.getUrlEncoder();



    public static String genPassHash(String password) {
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        return OpenBSDBCrypt.generate(password.toCharArray(), salt, 12);
    }

    public static String getToken() {
        byte[] bytes = new byte[24];
        secureRandom.nextBytes(bytes);
        return encoder.encodeToString(bytes);

    }

    public static boolean comparePassHash(String hash, String password) {
        return OpenBSDBCrypt.checkPassword(hash, password.toCharArray());
    }
}
