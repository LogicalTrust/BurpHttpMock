package net.logicaltrust.model;

import java.net.URL;

public enum MockProtocolEnum {

	ANY("Any") {
		public boolean matches(String protocol) {
			return true;
		}
	},
	
	HTTP("HTTP") {
		public boolean matches(String protocol) {
			return "http".equalsIgnoreCase(protocol);
		}
	},
	
	HTTPS("HTTPS") {
		public boolean matches(String protocol) {
			return "https".equalsIgnoreCase(protocol);
		}
	};
	
	public static MockProtocolEnum fromURL(URL url) {
		String proto = url.getProtocol();
		if ("http".equalsIgnoreCase(proto))
			return HTTP;
		if ("https".equalsIgnoreCase(proto))
			return HTTPS;
		return ANY;
	}
	
	private String protocol;
	
	private MockProtocolEnum(String protocol) {
		this.protocol = protocol;
	}
	
	public String getProtocol() {
		return protocol;
	}
	
	public abstract boolean matches(String protocol);
	
}
