package net.logicaltrust.server;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

import burp.IExtensionStateListener;
import net.logicaltrust.SimpleLogger;

public class MockLocalServer implements IExtensionStateListener {

	private SimpleLogger logger;
	private boolean stopped = false;
	private ServerSocket ss;
	private final int port;
	
	public MockLocalServer(SimpleLogger logger, int port) {
		this.logger = logger;
		this.port = port;
	}
	
	public void run() {
		try {
			ss = new ServerSocket(port, 50, InetAddress.getLoopbackAddress());
			logger.debugForce("Server has started " + ss);
			while (!isStopped()) {
				try {
					logger.debug("Waiting for connection");
					Socket accept = ss.accept();
					logger.debug("Connection " + accept + " accepted");
					BufferedReader br = new BufferedReader(new InputStreamReader(accept.getInputStream()));				    
					BufferedOutputStream bos = new BufferedOutputStream(accept.getOutputStream());
					bos.write("HTTP/1.0 418 I'm a teapot\r\nConnection: close\r\n\r\ntest".getBytes());
					bos.close();
					br.close();
					accept.close();
				} catch (IOException e) {
					if (isStopped()) {
						logger.debugForce("Server has stopped");
					} else {
						e.printStackTrace(logger.getStderr());
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace(logger.getStderr());
			logger.debugForce("Cannot create server. Try with another port.");
		}
	}
	
	private synchronized boolean isStopped() {
		return stopped;
	}
	
	public synchronized void setStopped(boolean stopped) {
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
