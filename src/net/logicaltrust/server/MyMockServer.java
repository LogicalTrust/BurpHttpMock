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

public class MyMockServer implements IExtensionStateListener {

	private SimpleLogger logger;
	private boolean stopped = false;
	private ServerSocket ss;
	
	public MyMockServer(SimpleLogger logger) {
		this.logger = logger;
	}
	
	public void run() {
		try {
			ss = new ServerSocket(8765, 50, InetAddress.getLoopbackAddress());
			logger.debugForce("Server has started " + ss);
			while (!isStopped()) {
				try {
					logger.debug("Waiting for connection");
					Socket accept = ss.accept();
					logger.debug("Connection " + accept + " accepted");
					BufferedReader br = new BufferedReader(new InputStreamReader(accept.getInputStream()));				    
					BufferedOutputStream bos = new BufferedOutputStream(accept.getOutputStream());
					bos.write("HTTP/1.0 200 File not found\nServer: SimpleHTTP/0.6 Python/2.7.15\nDate: Sun, 03 Jun 2018 11:28:24 GMT\nConnection: close\nContent-Type: text/html\n\n<head>\n<title>Error response</title>\n</head>\n<body>\n<h1>Error response</h1>\n<p>EOKOK OKOK 200.\n<p>Message: File not found.\n<p>AAAAA code explanation: 200 = Nothing matches the given URI.\n</body>".getBytes());
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
