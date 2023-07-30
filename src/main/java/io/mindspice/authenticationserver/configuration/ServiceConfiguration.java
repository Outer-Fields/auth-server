package io.mindspice.authenticationserver.configuration;

import com.google.code.kaptcha.Producer;
import com.google.code.kaptcha.impl.DefaultKaptcha;
import com.google.code.kaptcha.util.Config;
import io.mindspice.authenticationserver.http.HttpClient;
import io.mindspice.authenticationserver.service.AuthService;
import io.mindspice.authenticationserver.settings.AuthConfig;
import io.mindspice.authenticationserver.util.ProfanityCheck;
import io.mindspice.databaseservice.client.DBServiceClient;
import io.mindspice.databaseservice.client.api.OkraAuthAPI;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.awt.image.BufferedImage;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;


@Configuration
public class ServiceConfiguration {

    @Bean
    public HttpClient itemServerClient() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        return new HttpClient(AuthConfig.get().itemUri, AuthConfig.get().itemUser, AuthConfig.get().itemPassword);
    }

    @Bean
    DBServiceClient dbServiceClient() throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        return new DBServiceClient(AuthConfig.get().dbServiceUri, AuthConfig.get().dbServiceUser, AuthConfig.get().dbServicePass);
    }

    @Bean
    OkraAuthAPI okraAuthAPI(@Qualifier("dbServiceClient") DBServiceClient dbServiceClient) {
        return new OkraAuthAPI(dbServiceClient);
    }

    @Bean
    ProfanityCheck profanityCheck() {
        return new ProfanityCheck("profane.txt");
    }

    @Bean
    public AuthService authService(
            @Qualifier("okraAuthAPI") OkraAuthAPI okraAuthAPI,
            @Qualifier("profanityCheck") ProfanityCheck profanityCheck,
            @Qualifier("itemServerClient") HttpClient httpClient
    ) {
        return new AuthService(okraAuthAPI, profanityCheck, httpClient);
    }

    @Bean
    public Producer captchaProducer() {
        Properties properties = new Properties();
        properties.setProperty("kaptcha.textproducer.char.string", "23456789ABCDEFGHJKLMNPQRSTUVWXYZ@%*#");
        properties.setProperty("kaptcha.textproducer.char.length", "5");
        properties.setProperty("kaptcha.image.width", "200");
        properties.setProperty("kaptcha.image.height", "50");
        properties.setProperty("kaptcha.noise.color", "black");
        properties.setProperty("kaptcha.background.clear.from", "white");
        properties.setProperty("kaptcha.background.clear.to", "white");
        properties.setProperty("kaptcha.textproducer.font.color", "black");
        properties.setProperty("kaptcha.textproducer.font.size", "40");
        properties.setProperty("kaptcha.textproducer.font.names", "Arial");

        properties.setProperty("kaptcha.obscurificator.impl", "com.google.code.kaptcha.impl.WaterRipple");

        Config config = new Config(properties);
        DefaultKaptcha defaultKaptcha = new DefaultKaptcha();
        defaultKaptcha.setConfig(config);

        return defaultKaptcha;
    }
//    public Producer captchaProducer() {
//        Properties properties = new Properties();
//        properties.setProperty("kaptcha.textproducer.char.string", "23456789ABCDEFGHJKLMNPQRSTUVWXYZ");
//        properties.setProperty("kaptcha.textproducer.char.length", "6");
//        properties.setProperty("kaptcha.image.width", "150");
//        properties.setProperty("kaptcha.image.height", "50");
//        properties.setProperty("kaptcha.noise.color", "white");
//        properties.setProperty("kaptcha.background.clear.from", "white");
//        properties.setProperty("kaptcha.background.clear.to", "white");
//        properties.setProperty("kaptcha.textproducer.font.color", "black");
//        properties.setProperty("kaptcha.textproducer.font.size", "40");
//        properties.setProperty("kaptcha.textproducer.font.names", "Arial");
//
//        // Adding noise
//        properties.setProperty("kaptcha.noise.impl", "com.google.code.kaptcha.impl.DefaultNoise");
//
//        // Making the text more obscure
//        properties.setProperty("kaptcha.obscurificator.impl", "com.google.code.kaptcha.impl.ShadowGimpy");
//
//        Config config = new Config(properties);
//        DefaultKaptcha defaultKaptcha = new DefaultKaptcha();
//        defaultKaptcha.setConfig(config);
//
//        return defaultKaptcha;
//    }
}

