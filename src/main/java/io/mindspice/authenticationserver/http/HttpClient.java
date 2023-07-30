package io.mindspice.authenticationserver.http;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.core.JsonProcessingException;
import io.mindspice.databaseservice.client.Request;
import io.mindspice.mindlib.util.JsonUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

public class HttpClient {

    private final CloseableHttpClient client;
    private final String address;

    public HttpClient(String addr, String username, String password)
            throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException {

        address = addr;
        KeyStore keystore = KeyStore.getInstance("PKCS12");

        CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(username, password));

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(20_000)
                .setConnectionRequestTimeout(20_000)
                .setSocketTimeout(20_000).build();

        SSLContext sslContext = SSLContexts.custom()
                .loadTrustMaterial(TrustAllStrategy.INSTANCE)
                .build();

        client = HttpClients.custom()
                .setDefaultCredentialsProvider(credentialsProvider)
                .setDefaultRequestConfig(requestConfig)
                .setSSLContext(sslContext)
                .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                .build();
    }


    public String getAddress() {
        return address;
    }

    public byte[] makeRequest(String endpoint, byte[] data) throws IOException {
        URI uri = null;
        try {
            uri = new URI(address + endpoint);
        } catch (URISyntaxException e) {
            throw new RuntimeException("Invalid URI: " + uri);
        }
        var httpPost = new HttpPost(uri);
        httpPost.setEntity(new ByteArrayEntity(data));
        httpPost.setHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType());

        try (CloseableHttpResponse response = client.execute(httpPost)) {
            System.out.println(response);
            InputStream content = response.getEntity().getContent();
            byte[] bytes = content.readAllBytes();
            return bytes;
        }
    }

    public void mintAccountNft(int playerId, String address)  {
        try {
            byte[] request = new JsonUtils.ObjectBuilder()
                    .put("player_id", playerId)
                    .put("address", address)
                    .buildBytes();
            makeRequest("/mint_account_nft", request);
        } catch (Exception ignored) {
        }
    }
}