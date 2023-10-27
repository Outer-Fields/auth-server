package io.mindspice.authenticationserver.api;

import com.google.code.kaptcha.Producer;
import io.mindspice.authenticationserver.data.incoming.Auth;
import io.mindspice.authenticationserver.data.incoming.PassReset;
import io.mindspice.authenticationserver.data.incoming.Register;
import io.mindspice.authenticationserver.data.outgoing.Authorization;
import io.mindspice.authenticationserver.service.AuthService;
import io.mindspice.authenticationserver.settings.AuthConfig;
import io.mindspice.authenticationserver.util.Crypto;
import io.mindspice.authenticationserver.util.Log;
import io.mindspice.jxch.rpc.util.JsonUtils;
import io.mindspice.mindlib.data.Pair;
import jakarta.servlet.http.HttpSession;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Map;


@RestController
@CrossOrigin(origins = "*", allowedHeaders = {"session-id", "user-agent", "content-type"}, exposedHeaders = {"session-id"})

//@CrossOrigin
@RequestMapping("/api")
public class AccountController {
    private final AuthService authService;
    private final Producer captchaProducer;
    private final Map<String, Pair<String, Long>> sessionTable;

    public AccountController(AuthService authService, Producer captchaProducer) {
        this.authService = authService;
        this.captchaProducer = captchaProducer;
        this.sessionTable = authService.getSessionTable();
    }

    @PostMapping("/login")
    public ResponseEntity<Authorization> login(
            @RequestHeader("CF-Connecting-IP") String originIp,
            @RequestHeader(value = "session-id", required = false) String sessionID,
            @RequestBody Auth auth) {
        if (AuthConfig.get().isPaused) { return new ResponseEntity<>(HttpStatus.SERVICE_UNAVAILABLE); }

        try {
            if (sessionID == null || auth.captcha() == null) {
                var authorization = new Authorization(HttpStatus.UNAUTHORIZED, "Client Error.");
                return new ResponseEntity<>(authorization, HttpStatus.UNAUTHORIZED);
            }

            HttpHeaders headers = new HttpHeaders();
            headers.set("session-id", sessionID);

            Pair<String, Long> session = sessionTable.get(sessionID);
            if (session == null) {
                var authorization = new Authorization(HttpStatus.UNAUTHORIZED, "Stale Captcha, Try Again.");
                return new ResponseEntity<>(authorization, headers, HttpStatus.UNAUTHORIZED);
            }

            if (!auth.captcha().equals(session.first())) {
                var authorization = new Authorization(HttpStatus.UNAUTHORIZED, "Invalid Captcha");
                sessionTable.remove(sessionID);
                return new ResponseEntity<>(authorization, headers, HttpStatus.UNAUTHORIZED);
            }
            sessionTable.remove(sessionID);
            Authorization authorization = authService.authenticate(originIp, auth);
            return new ResponseEntity<>(authorization, headers, authorization.httpStatus());
        } catch (Exception e) {
            Log.SERVER.error(this.getClass(), "/login threw exception:", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(
            @RequestHeader("CF-Connecting-IP") String originIp,
            @RequestHeader(value = "session-id", required = false) String sessionID,
            @RequestBody Register register) {
        if (AuthConfig.get().isPaused) { return new ResponseEntity<>(HttpStatus.SERVICE_UNAVAILABLE); }

        try {
            if (sessionID == null || register.captcha() == null) {
                return new ResponseEntity<>("Client Error.", HttpStatus.UNAUTHORIZED);
            }
            HttpHeaders headers = new HttpHeaders();
            headers.set("session-id", sessionID);

            Pair<String, Long> session = sessionTable.get(sessionID);
            if (session == null) {
                return new ResponseEntity<>("Stale Captcha, Try Again.", headers, HttpStatus.UNAUTHORIZED);
            }

            if (!register.captcha().equals(session.first())) {
                sessionTable.remove(sessionID);
                return new ResponseEntity<>("Invalid Captcha", headers, HttpStatus.UNAUTHORIZED);
            }

            Pair<HttpStatus, String> regReturn = authService.register(originIp, register);
            sessionTable.remove(sessionID);
            return new ResponseEntity<>(regReturn.second(), headers, regReturn.first());
        } catch (Exception e) {
            Log.SERVER.error(this.getClass(), "/register threw exception:", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/reset_password")
    public ResponseEntity<String> resetPassword(
            @RequestHeader("CF-Connecting-IP") String originIp,
            @RequestHeader(value = "session-id", required = false) String sessionID,
            @RequestBody PassReset passReset) {
        if (AuthConfig.get().isPaused) { return new ResponseEntity<>(HttpStatus.SERVICE_UNAVAILABLE); }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("session-id", sessionID);
            Pair<String, Long> session = sessionTable.get(sessionID);
            if (session == null) {
                return new ResponseEntity<>("Stale Captcha, Try Again.", headers, HttpStatus.UNAUTHORIZED);
            }

            if (!passReset.captcha().equals(session.first())) {
                sessionTable.remove(sessionID);
                return new ResponseEntity<>("Invalid Captcha", headers, HttpStatus.UNAUTHORIZED);
            }

            Pair<HttpStatus, String> resetReturn = authService.resetPassword(originIp, passReset);
            sessionTable.remove(sessionID);
            return new ResponseEntity<>(resetReturn.second(), headers, resetReturn.first());
        } catch (Exception e) {
            Log.SERVER.error(this.getClass(), "/reset_password threw exception:", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/captcha")
    public ResponseEntity<byte[]> captcha(@RequestHeader("CF-Connecting-IP") String originIp,
            @RequestHeader(value = "session-id", required = false) String sessionID)
            throws IOException {
        if (AuthConfig.get().isPaused) { return new ResponseEntity<>(HttpStatus.SERVICE_UNAVAILABLE); }

        try {

            String captchaText = captchaProducer.createText();
            BufferedImage captchaImage = captchaProducer.createImage(captchaText);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(captchaImage, "jpg", baos);
            byte[] imageData = baos.toByteArray();

            HttpHeaders headers = new HttpHeaders();
            if (sessionID == null || sessionTable.get(sessionID) == null) {
                String newId = Crypto.getToken();
                headers.set("session-id", newId);
                sessionTable.put(newId, new Pair<>(captchaText, Instant.now().getEpochSecond()));
            } else {
                sessionTable.put(sessionID, new Pair<>(captchaText, Instant.now().getEpochSecond())); // changed
                headers.set("session-id", sessionID);
            }

            return ResponseEntity.status(HttpStatus.OK)
                    .headers(headers)
                    .contentType(MediaType.IMAGE_JPEG)
                    .body(imageData);
        } catch (Exception e) {
            Log.SERVER.error(this.getClass(), "/captcha threw exception:", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/reauth")
    public ResponseEntity<String> reauth(@RequestHeader("CF-Connecting-IP") String originIp,
            @RequestHeader(value = "session-id", required = false) String sessionID,
            @RequestBody String token) {

        if (AuthConfig.get().isPaused) { return new ResponseEntity<>(HttpStatus.SERVICE_UNAVAILABLE); }

        try {
            if (token == null || token.isEmpty()) {
                Log.ABUSE.info(this.getClass(), "Reauth attempt without token by:" + originIp);
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }
            int playerId = authService.getIdForToken(token);
            if (playerId != -1) {
                String tempToken = authService.newTempAuth(playerId);
                return new ResponseEntity<>(tempToken, HttpStatus.OK);
            } else {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }
        } catch (Exception e) {
            Log.SERVER.error(this.getClass(), "/reauth threw exception:", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
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
