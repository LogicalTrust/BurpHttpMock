package net.logicaltrust;

import burp.IHttpService;

public class LocalHttpService implements IHttpService {

	private final String host;
	private final int port;
	private final String proto;
	
	public LocalHttpService(String host, int port, String proto) {
		this.host = host;
		this.port = port;
		this.proto = proto;
	}
	
	public LocalHttpService() {
		this("localhost", 4444, "http");
	}

	@Override
	public String getHost() {
		return host;
	}

	@Override
	public int getPort() {
		return port;
	}

	@Override
	public String getProtocol() {
		return proto;
	}

}
