package org.apache.geronimo.microprofile.impl.jwtauth.jwt;

import static javax.ws.rs.client.ClientBuilder.newClient;
import static org.testng.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URISyntaxException;
import java.net.URL;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.testng.annotations.AfterClass;
import org.testng.annotations.Test;

public class KidMapperTest extends Arquillian {

	private static Server jwksServer;

    @Deployment()
    public static WebArchive createDeployment() throws Exception {
        jwksServer = new Server();
        jwksServer.start();
        System.setProperty("mp.jwt.verify.publickey.location", "http://localhost:" + jwksServer.getPort() + "/jwks.json");
        return ShrinkWrap
            .create(WebArchive.class)
            .addAsWebInfResource("META-INF/beans.xml", "beans.xml")
            .addClasses(JwtParser.class, KidMapper.class);
    }

    @AfterClass
    static void stopJwksServer() throws IOException {
        jwksServer.stop();
    }

    @ArquillianResource
    private URL serverUrl;

    @Test
    @RunAsClient
    void convertJwksetToPem() throws URISyntaxException {
        String expectedKey = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyzNurU19lqnYhx5QI72sIX1lh8cTehTmboC+DLG7UuaUHqs096M754HtP2IiHFcIQqwYNzHgKmjmfGdbk9JBkz/DNeDVsA5nc7qTnsSgULXTxwHSF286IJdco5kasaJm4Xurlm3V+2oiTugraBsi1J0Ht0OtHgJIlIaGxK7mY/QIDAQAB-----END PUBLIC KEY-----";

        String key = newClient().target(serverUrl.toURI()).path("public-keys").path("orange-1234").request().get(String.class);
        
        assertEquals(key, expectedKey);
    }

    @ApplicationScoped
    @Path("public-keys")
    public static class PublicKeyResource {

        @Inject
        private KidMapper kidMapper;

        @GET
        @Path("{kid}")
        @Produces()
        public String getPublicKey(@PathParam("kid") String kid) {
            return kidMapper.loadKey(kid);
        }
    }

    private static class Server {

        private static final String HEADER = "HTTP/1.0 200 OK\r\nConnection: close\r\n";

        private ServerSocket serverSocket;

        Server() throws IOException {
            serverSocket = new ServerSocket(0);
        }

        int getPort() {
            return serverSocket.getLocalPort();
        }

        void start() {
            Thread server = new Thread(() -> {
                while (!serverSocket.isClosed()) {
                    try (Socket client = serverSocket.accept();
                            BufferedReader request = new BufferedReader(new InputStreamReader(client.getInputStream()));
                            BufferedReader reader = new BufferedReader(new InputStreamReader(
                                    getClass().getResourceAsStream(request.readLine().split("\\s")[1])));
                            PrintWriter writer = new PrintWriter(client.getOutputStream())) {

                        writer.println(HEADER);
                        writer.print(load(reader));
                    } catch (IOException e) {
                        if (!serverSocket.isClosed()) {
                            e.printStackTrace(System.err);
                        }
                    }
                }
            });
            server.start();
        }

        void stop() throws IOException {
            serverSocket.close();
        }

        private String load(BufferedReader reader) throws IOException {
            StringBuilder content = new StringBuilder();
            for (String line = reader.readLine(); line != null; line = reader.readLine()) {
                content.append(line).append("\r\n");
            }
            return content.toString();
        }
    }
}