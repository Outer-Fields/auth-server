package io.mindspice.authenticationserver;

import com.google.code.kaptcha.Producer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

@SpringBootTest
class KaptchaTest {

    @Autowired
    private Producer captchaProducer;

    @Test
    void generateCaptchaImage() {
        // Generate the captcha text
        String capText = captchaProducer.createText();

        // Generate the captcha image
        BufferedImage bi = captchaProducer.createImage(capText);

        // Save the captcha image to the disk
        File outputfile = new File("saved.png");
        try {
            ImageIO.write(bi, "png", outputfile);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}