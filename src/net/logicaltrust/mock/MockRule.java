package net.logicaltrust.mock;

import java.net.URL;
import java.util.regex.Pattern;

public class MockRule {

	private String protocol;
	private String host;
	private String port;
	private String path;
	
	private Pattern pathRegex;
	private Pattern portRegex;
	private Pattern hostRegex;

	public MockRule(String protocol, String host, String port, String path) {
		this.setHost(host);
		this.setPath(path);
		this.setPort(port);
		this.protocol = protocol;
	}
	
	public boolean matches(URL url) {
		return protocol.equalsIgnoreCase(url.getProtocol()) 
				&& hostRegex.matcher(url.getHost()).matches()
				&& portRegex.matcher(url.getPort()+"").matches()
				&& pathRegex.matcher(url.getFile()).matches();
	}
	
	public String getHost() {
		return host;
	}

	public String getPort() {
		return port;
	}

	public String getPath() {
		return path;
	}

	public String getProtocol() {
		return protocol;
	}

	public void setHost(String host) {
		this.host = host;
		this.hostRegex = Pattern.compile(host);
	}

	public void setPort(String port) {
		this.port = port;
		this.portRegex = Pattern.compile(port);
	}

	public void setPath(String path) {
		this.path = path;
		this.pathRegex = Pattern.compile(path);
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	@Override
	public String toString() {
		return "MockRule [protocol=" + protocol + ", host=" + host + ", port=" + port + ", path=" + path + "]";
	}
	
}
