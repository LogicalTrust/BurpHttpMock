package net.logicaltrust.mock;

public class MockEntry {

	private long id;
	private MockRule rule;
	private byte[] response;
	
	public MockEntry(MockRule rule, byte[] response) {
		this.rule = rule;
		this.response = response;
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

	public MockRule getRule() {
		return rule;
	}
	
	public void setRule(MockRule rule) {
		this.rule = rule;
	}

}
