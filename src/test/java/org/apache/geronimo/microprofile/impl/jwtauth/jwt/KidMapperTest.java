package org.apache.geronimo.microprofile.impl.jwtauth.jwt;

import static org.testng.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

@Test()
public class KidMapperTest {

	private Server jwksServer;

	@BeforeTest
	void startJwksServer() throws IOException {
		jwksServer = new Server();
		jwksServer.start();
	}

	@AfterTest
	void stopJwksServer() throws IOException {
		jwksServer.stop();
	}

	@Test
	void convertJwksetToPem() {
		KidMapper kidMapper = new KidMapper();
		String localJwksUrl = "http://localhost:" + jwksServer.getPort() + "/jwks.json";
		kidMapper.config = (key, defaultValue) -> "verify.publickey.location".equals(key) ? localJwksUrl : null;
		kidMapper.init();

		String key = kidMapper.loadKey("orange-1234");
		String expectedKey = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyzNurU19lqnYhx5QI72sIX1lh8cTehTmboC+DLG7UuaUHqs096M754HtP2IiHFcIQqwYNzHgKmjmfGdbk9JBkz/DNeDVsA5nc7qTnsSgULXTxwHSF286IJdco5kasaJm4Xurlm3V+2oiTugraBsi1J0Ht0OtHgJIlIaGxK7mY/QIDAQAB-----END PUBLIC KEY-----";
		assertEquals(key, expectedKey);
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
							BufferedReader request = new BufferedReader(
									new InputStreamReader(client.getInputStream()));
							BufferedReader reader = new BufferedReader(
									new InputStreamReader(getClass().getResourceAsStream(request.readLine().split("\\s")[1])));
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