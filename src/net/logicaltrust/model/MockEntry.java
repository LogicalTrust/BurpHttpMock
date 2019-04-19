package net.logicaltrust.model;

import burp.IHttpRequestResponse;
import burp.IHttpService;
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
	private byte[] entryInput;
	
	public MockEntry(boolean enabled, MockRule rule, byte[] entryInput) {
		this.rule = rule;
		this.entryInput = entryInput == null ? DEFAULT_RESPONSE : entryInput;
		this.enabled = enabled;
	}
	
	public void setId(long id) {
		this.id = id;
	}
	
	public long getId() {
		return id;
	}
	
	public byte[] getEntryInput() {
		return entryInput;
	}
	
	public void setEntryInput(byte[] entryInput) {
		this.entryInput = entryInput;
	}

	//returns true if the function has handled the request
	// (and therefore the default behavior of redirecting the request should not be used)
	public boolean handleRequest(IHttpRequestResponse request)
	{
		MockEntryTypeEnum type = getEntryType();
		byte[] entryInput = getEntryInput();
		if (type != MockEntryTypeEnum.DirectEntry) entryInput = Arrays.copyOfRange(entryInput, 1, entryInput.length);
		return getEntryType().handleRequest(entryInput, request);
	}

	public byte[] handleResponse(byte[] request, IHttpService service)
	{
	    MockEntryTypeEnum type = getEntryType();
	    byte[] entryInput = getEntryInput();
	    if (type != MockEntryTypeEnum.DirectEntry) entryInput = Arrays.copyOfRange(entryInput, 1, entryInput.length);
	    return type.generateResponse(entryInput, request, service);
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

	public MockEntryTypeEnum getEntryType() {
		Map<String, MockEntryTypeEnum> prefixMap = new HashMap<>();
		prefixMap.put("!", MockEntryTypeEnum.CgiScript);
		prefixMap.put("#", MockEntryTypeEnum.FileInclusion);
		prefixMap.put("%", MockEntryTypeEnum.UrlRedirect);
		prefixMap.put("|", MockEntryTypeEnum.Pipe);


		entryLoop:
		for (Map.Entry<String, MockEntryTypeEnum> e: prefixMap.entrySet())
		{
			byte[] prefix = e.getKey().getBytes();
			if (prefix.length >= getEntryInput().length) continue;
			for (int i = 0; i < prefix.length; i++) {
				if (prefix[i] != getEntryInput()[i]) continue entryLoop;
			}
			return e.getValue();
		}
		return MockEntryTypeEnum.DirectEntry;
	}
	
	public Object[] toObject() {
		return new Object[] { enabled, getRule().getProtocol(), getRule().getHost(), getRule().getPort(), getRule().getPath() };
	}

	@Override
	public String toString() {
		return "MockEntry [id=" + id + ", enabled=" + enabled + ", rule=" + rule + "]";
	}
	
	public MockEntry duplicate() {
		return new MockEntry(this.enabled, this.rule.duplicate(), Arrays.copyOf(entryInput, entryInput.length));
	}

}
