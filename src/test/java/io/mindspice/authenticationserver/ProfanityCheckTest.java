package io.mindspice.authenticationserver;

import io.mindspice.authenticationserver.util.ProfanityChecker;
import io.mindspice.databaseservice.client.util.Util;
import org.junit.jupiter.api.Test;


public class ProfanityCheckTest {


    @Test

    void profanityTest() {

        System.out.println(ProfanityChecker.check("fagg0t"));
    }

    @Test
    void utilTest() {
        System.out.println(Util.normalizeHex("d86dedaf1123b7ec943070b00ffe80e50bc38844420287370374016b96f5d5a8"));
    }
}
