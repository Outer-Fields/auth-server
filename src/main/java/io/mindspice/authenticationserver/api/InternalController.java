package io.mindspice.authenticationserver.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mindspice.authenticationserver.data.ConfirmInfo;
import io.mindspice.authenticationserver.service.AuthService;
import io.mindspice.authenticationserver.settings.AuthConfig;
import io.mindspice.authenticationserver.util.Log;
import io.mindspice.mindlib.util.JsonUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;


@CrossOrigin
@RestController
@RequestMapping("/internal")
public class InternalController {
    private final AuthService authService;

    @Autowired
    public InternalController(AuthService authService) { this.authService = authService; }

    @PostMapping("/player_id_from_token")
    public ResponseEntity<Integer> playerIdFromToken(@RequestBody String req) throws JsonProcessingException {
        try {
            String token = JsonUtils.readTree(req).get("token").asText();
            return new ResponseEntity<>(authService.getIdForToken(token), HttpStatus.OK);
        } catch (Exception e) {
            Log.SERVER.error(this.getClass(), "/player_id_from_token threw exception:",  e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<Integer> authenticate(@RequestBody String req) throws JsonProcessingException {
        try {
            String token = JsonUtils.readTree(req).get("token").asText();
            return new ResponseEntity<>(authService.validateTempAuth(token), HttpStatus.OK);
        } catch (Exception e) {
            Log.SERVER.error(this.getClass(), "/authenticate threw exception:",  e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("set_paused")
    public ResponseEntity<Integer> setPaused(@RequestBody String req) throws JsonProcessingException {
        try {
            AuthConfig.get().isPaused = JsonUtils.readTree(req).get("is_paused").asBoolean();
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (Exception e) {
            Log.SERVER.error(this.getClass(), "/set_paused threw exception:",  e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @PostMapping("/health")
    public ResponseEntity<String> health(@RequestBody String req) throws JsonProcessingException {
        try {
            String ping = JsonUtils.readTree(req).get("ping").asText();
            return new ResponseEntity<>(JsonUtils.writeString(JsonUtils.newSingleNode("pong", ping)), HttpStatus.OK);
        } catch (Exception e) {
            Log.SERVER.error(this.getClass(), "/health threw exception:",  e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
