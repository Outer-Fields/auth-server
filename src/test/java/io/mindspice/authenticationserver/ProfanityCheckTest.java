package io.mindspice.authenticationserver;

import io.mindspice.authenticationserver.util.ProfanityCheck;
import io.mindspice.databaseservice.client.util.Util;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.context.junit4.SpringRunner;


public class ProfanityCheckTest {


    @Test

    void profanityTest() {
        ProfanityCheck profanityCheck = new ProfanityCheck("profane.txt");

        System.out.println(profanityCheck.profanityCheck("dikeboy"));
    }

    @Test
    void utilTest() {
        System.out.println(Util.normalizeHex("d86dedaf1123b7ec943070b00ffe80e50bc38844420287370374016b96f5d5a8"));
    }
}
