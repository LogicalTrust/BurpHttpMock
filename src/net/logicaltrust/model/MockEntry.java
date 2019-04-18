package net.logicaltrust.model;

import com.google.gson.annotations.Expose;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class MockEntry {

	private static final byte[] DEFAULT_RESPONSE = "HTTP/1.1 200 OK\r\nConnection: close\r\n".getBytes(StandardCharsets.UTF_8);
	
	private long id;

	@Expose
	private boolean enabled;

	@Expose
	private MockRule rule;

	@Expose
	private byte[] responseData;
	
	public MockEntry(boolean enabled, MockRule rule, byte[] responseData) {
		this.rule = rule;
		this.responseData = responseData == null ? DEFAULT_RESPONSE : responseData;
		this.enabled = enabled;
	}
	
	public void setId(long id) {
		this.id = id;
	}
	
	public long getId() {
		return id;
	}
	
	public byte[] getResponseData() {
		return responseData;
	}
	
	public void setResponseData(byte[] responseData) {
		this.responseData = responseData;
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

	public MockResponseTypeEnum getResponseType() {
		Map<String, MockResponseTypeEnum> prefixMap = new HashMap<>();
		prefixMap.put("!", MockResponseTypeEnum.CgiScript);
		prefixMap.put("#", MockResponseTypeEnum.FileInclusion);
		prefixMap.put("%", MockResponseTypeEnum.UrlRedirect);

		entryLoop:
		for (Map.Entry<String, MockResponseTypeEnum> e: prefixMap.entrySet())
		{
			byte[] prefix = e.getKey().getBytes();
			if (prefix.length >= getResponseData().length) continue;
			for (int i = 0; i < prefix.length; i++) {
				if (prefix[i] != getResponseData()[i]) continue entryLoop;
			}
			return e.getValue();
		}
		return MockResponseTypeEnum.DirectEntry;
	}
	
	public Object[] toObject() {
		return new Object[] { enabled, getRule().getProtocol(), getRule().getHost(), getRule().getPort(), getRule().getPath() };
	}

	@Override
	public String toString() {
		return "MockEntry [id=" + id + ", enabled=" + enabled + ", rule=" + rule + "]";
	}
	
	public MockEntry duplicate() {
		return new MockEntry(this.enabled, this.rule.duplicate(), Arrays.copyOf(responseData, responseData.length));
	}

}
