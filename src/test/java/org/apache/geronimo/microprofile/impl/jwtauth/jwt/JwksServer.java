package org.apache.geronimo.microprofile.impl.jwtauth.jwt;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

class JwksServer {

    private static final String HEADER = "HTTP/1.0 200 OK\r\nConnection: close\r\n";

    private ServerSocket serverSocket;

    JwksServer() throws IOException {
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