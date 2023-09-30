package io.mindspice.authenticationserver.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mindspice.authenticationserver.service.AuthService;
import io.mindspice.mindlib.util.JsonUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@CrossOrigin
@RestController
@RequestMapping("/internal")
public class InternalController {
    private final AuthService authService;

    @Autowired
    public InternalController(AuthService authService) { this.authService = authService; }

    @PostMapping("/player_id_from_token")
    public ResponseEntity<Integer> playerIdFromToken(@RequestBody String req) throws JsonProcessingException {
        String token = JsonUtils.readTree(req).get("token").asText();
        return new ResponseEntity<>(authService.getIdForToken(token), HttpStatus.OK);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<Integer> authenticate(@RequestBody String req) throws JsonProcessingException {
        String token = JsonUtils.readTree(req).get("token").asText();
        return new ResponseEntity<>(authService.validateTempAuth(token), HttpStatus.OK);
    }

    @PostMapping("/health")
    public ResponseEntity<String> health(@RequestBody String req) throws JsonProcessingException {
        String ping = JsonUtils.readTree(req).get("ping").asText();
        return new ResponseEntity<>(JsonUtils.writeString(JsonUtils.newSingleNode("pong", ping)), HttpStatus.OK);
    }
}
