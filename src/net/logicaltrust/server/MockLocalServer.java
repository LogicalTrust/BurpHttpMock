package net.logicaltrust.server;

import burp.BurpExtender;
import burp.IExtensionStateListener;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import fi.iki.elonen.NanoHTTPD;
import net.logicaltrust.SimpleLogger;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class MockLocalServer implements IExtensionStateListener {

    private final SimpleLogger logger;
    private final int port;
    private Server server;

    public MockLocalServer(int port) {
        this.logger = BurpExtender.getLogger();
        this.port = port;
    }

    private static class Server extends NanoHTTPD {
        Server(int port) {
            super("127.0.0.1", port);
        }
    }

    public void run() {
        try {
            server = new Server(port);
            server.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);
            logger.debugForce("Server has started, port=" + port);
        } catch (IOException e) {
            e.printStackTrace(logger.getStderr());
            logger.debugForce("Cannot create server. Try with another port.");
        }
    }

    @Override
    public void extensionUnloaded() {
        try {
            server.stop();
        } catch (Exception e) {
            e.printStackTrace(logger.getStderr());
        }
    }

}
