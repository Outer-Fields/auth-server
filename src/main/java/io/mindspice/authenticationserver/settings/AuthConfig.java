package io.mindspice.authenticationserver.settings;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.File;
import java.io.IOException;


public class AuthConfig {
    private static AuthConfig INSTANCE;

    public volatile long loginTimeout;
    public volatile long tokenTimeout;
    public volatile String itemUri = "";
    public volatile String itemUser = "";
    public volatile String itemPassword = "";
    public volatile String dbServiceUri = "";
    public volatile String dbServiceUser = "";
    public volatile String dbServicePass = "";
    public volatile boolean isPaused = false;

    static {
        try {
            AuthConfig.writeBlank();
        } catch (IOException e) {
        }
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        mapper.findAndRegisterModules();

        File file = new File("config.yaml");

        try {
            INSTANCE = mapper.readValue(file, AuthConfig.class);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read config file.", e);
        }
        System.out.println(get().toString());
    }

    public static AuthConfig get() {
        return INSTANCE;
    }


    public static void writeBlank() throws IOException {
        var mapper = new ObjectMapper(new YAMLFactory());
        mapper.setSerializationInclusion(JsonInclude.Include.ALWAYS);
        File yamlFile = new File("defaults.yaml");
        mapper.writeValue(yamlFile, new AuthConfig());
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("AuthConfig: ");
        sb.append("\n  loginTimeout: ").append(loginTimeout);
        sb.append(",\n  tokenTimeout: ").append(tokenTimeout);
        sb.append(",\n  itemUri: \"").append(itemUri).append('\"');
        sb.append(",\n  itemUser: \"").append(itemUser).append('\"');
        sb.append(",\n  itemPassword: \"").append(itemPassword).append('\"');
        sb.append(",\n  dbServiceUri: \"").append(dbServiceUri).append('\"');
        sb.append(",\n  dbServiceUser: \"").append(dbServiceUser).append('\"');
        sb.append(",\n  dbServicePass: \"").append(dbServicePass).append('\"');
        sb.append("\n");
        return sb.toString();
    }
}
