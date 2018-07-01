package net.logicaltrust.model;

import java.net.URL;
import java.util.regex.Pattern;

public class MockRule {
	
	private MockProtocolEnum protocol;
	private String host;
	private String port;
	private String path;
	
	private Pattern pathRegex;
	private Pattern portRegex;
	private Pattern hostRegex;

	public MockRule(MockProtocolEnum protocol, String host, String port, String path) {
		this.setHost(host);
		this.setPath(path);
		this.setPort(port);
		this.protocol = protocol;
	}
	
	public MockRule(URL url) {
		this(MockProtocolEnum.fromURL(url), 
				decorateFull(url.getHost()), 
				decorateFull((url.getPort() != -1 ? url.getPort() : url.getDefaultPort()) + ""), 
				decorateFromStart(url.getPath()));
	}
	
	public boolean matches(URL url) {
		return protocol.matches(url.getProtocol()) 
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

	public MockProtocolEnum getProtocol() {
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

	public void setProtocol(MockProtocolEnum protocol) {
		this.protocol = protocol;
	}
	
	private static String decorateFull(String value) {
		return "^" + quote(value) + "$";
	}
	
	private static String decorateFromStart(String value) {
		return "^" + quote(value) + ".*";
	}
	
	private static String quote(String value) {
		return value.replaceAll("\\.", "\\\\.");
	}

	@Override
	public String toString() {
		return "MockRule [protocol=" + protocol + ", host=" + host + ", port=" + port + ", path=" + path + "]";
	}
	
}
