package net.logicaltrust.mock;

import java.nio.charset.StandardCharsets;

public class MockEntry {

	private static final byte[] DEFAULT_RESPONSE = "HTTP/1.1 200 OK\r\nConnection: close\r\n".getBytes(StandardCharsets.UTF_8);
	
	private long id;
	private boolean enabled;
	private MockRule rule;
	private byte[] response;
	
	public MockEntry(boolean enabled, MockRule rule, byte[] response) {
		this.rule = rule;
		this.response = response == null ? DEFAULT_RESPONSE : response;
		this.enabled = enabled;
	}
	
	public void setId(long id) {
		this.id = id;
	}
	
	public long getId() {
		return id;
	}
	
	public byte[] getResponse() {
		return response;
	}
	
	public void setResponse(byte[] response) {
		this.response = response;
	}

	public MockRule getRule() {
		return rule;
	}
	
	public void setRule(MockRule rule) {
		this.rule = rule;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	@Override
	public String toString() {
		return "MockEntry [id=" + id + ", enabled=" + enabled + ", rule=" + rule + "]";
	}

}
