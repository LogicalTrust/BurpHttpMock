package net.logicaltrust.server;

import burp.BurpExtender;
import burp.IExtensionStateListener;
import net.logicaltrust.SimpleLogger;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class MockLocalServer implements IExtensionStateListener {

    private final SimpleLogger logger;
    private final int port;
    private boolean stopped = false;
    private ServerSocket ss;

    public MockLocalServer(int port) {
        this.logger = BurpExtender.getLogger();
        this.port = port;
    }

    public void run() {
        try {
            ss = new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
            logger.debugForce("Server has started " + ss);
            while (!isStopped()) {
                serve();
            }
        } catch (IOException e) {
            e.printStackTrace(logger.getStderr());
            logger.debugForce("Cannot create server. Try with another port.");
        }
    }

    private void serve() {
        try {
            logger.debug("Waiting for connection");
            handleConnection(ss.accept());
        } catch (IOException e) {
            if (isStopped()) {
                logger.debugForce("Server has stopped");
            } else {
                e.printStackTrace(logger.getStderr());
            }
        }
    }

    private void handleConnection(Socket accept) throws IOException {
        logger.debug("Connection " + accept + " accepted");
        BufferedReader br = new BufferedReader(new InputStreamReader(accept.getInputStream()));
        BufferedOutputStream bos = new BufferedOutputStream(accept.getOutputStream());
        bos.write("HTTP/1.0 292 Mock\r\nContent-Type: application/x\r\n\r\n".getBytes());
        bos.close();
        br.close();
        accept.close();
    }

    private synchronized boolean isStopped() {
        return stopped;
    }

    private synchronized void setStopped(boolean stopped) {
        this.stopped = stopped;
    }

    @Override
    public void extensionUnloaded() {
        setStopped(true);
        try {
            ss.close();
        } catch (IOException e) {
            e.printStackTrace(logger.getStderr());
        }
    }

}
