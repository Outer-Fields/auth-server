package io.mindspice.authenticationserver.api;

import com.fasterxml.jackson.databind.introspect.Annotated;
import com.google.code.kaptcha.Producer;
import io.mindspice.authenticationserver.data.incoming.Auth;
import io.mindspice.authenticationserver.data.incoming.Register;
import io.mindspice.authenticationserver.data.outgoing.Authorization;
import io.mindspice.authenticationserver.data.outgoing.ReturnCode;
import io.mindspice.authenticationserver.service.AuthService;
import io.mindspice.mindlib.data.Pair;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;


@RestController
@CrossOrigin
@RequestMapping("/auth")
public class AccountController {
    private final AuthService authService;
    private final  Producer captchaProducer;

    public AccountController(AuthService authService, Producer captchaProducer) {
        this.authService = authService;
        this.captchaProducer = captchaProducer;
    }

    @PostMapping("/login")
    public ResponseEntity<Authorization> login(@RequestBody Auth auth, HttpSession session) {

        System.out.println("here");
        String sessionCaptcha = (String) session.getAttribute("captcha");
        System.out.println("login id:" + session.getId());
        System.out.println(sessionCaptcha);

        if (sessionCaptcha == null || auth.captcha() == null || !auth.captcha().equals(sessionCaptcha)) {
            var authorization = new Authorization(HttpStatus.UNPROCESSABLE_ENTITY, "Invalid Captcha");
            session.removeAttribute("captcha");
            return new ResponseEntity<>(authorization, HttpStatus.UNPROCESSABLE_ENTITY);
        }

        Authorization authorization = authService.authenticate(auth);
        return new ResponseEntity<>(authorization, authorization.httpStatus());
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody Register register, HttpSession session) {
        String sessionCaptcha = (String) session.getAttribute("captcha");

        if (sessionCaptcha == null || register.captcha() == null || !register.captcha().equals(sessionCaptcha)) {
            ReturnCode code =  ReturnCode.INVALID_CAPTCHA;
            session.removeAttribute("captcha");
            return new ResponseEntity<>("Invalid Captcha", HttpStatus.UNPROCESSABLE_ENTITY);
        }

        Pair<HttpStatus, String> regReturn = authService.register(register);

        return new ResponseEntity<>(regReturn.second(), regReturn.first());
    }
    @GetMapping("/captcha")
    public ResponseEntity<byte[]> captcha(HttpServletResponse response, HttpSession session) throws IOException {
        // generate the captcha text and image
        String captchaText = captchaProducer.createText();
        BufferedImage captchaImage = captchaProducer.createImage(captchaText);

        // store the captcha text in the session
        session.setAttribute("captcha", captchaText);
        System.out.println("captcha id:" + session.getId());
        // convert BufferedImage to byte array
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(captchaImage, "jpg", baos);
        byte[] imageData = baos.toByteArray();

        // Return a ResponseEntity with status OK and appropriate media type
        return ResponseEntity.status(HttpStatus.OK)
                .contentType(MediaType.IMAGE_JPEG)
                .body(imageData);
    }

//    @GetMapping("/captcha")

//    public void captcha(HttpServletResponse response, HttpSession session) throws IOException {
//        // generate the captcha text and image
//        String captchaText = captchaProducer.createText();
//        BufferedImage captchaImage = captchaProducer.createImage(captchaText);
//
//        // store the captcha text in the session
//        session.setAttribute("captcha", captchaText);
//
//        // write the image data to the response output stream
//        response.setContentType("image/jpeg");
//        ImageIO.write(captchaImage, "jpg", response.getOutputStream());
//
//    }
}
