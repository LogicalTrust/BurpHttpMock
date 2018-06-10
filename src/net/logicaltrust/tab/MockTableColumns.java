package net.logicaltrust.tab;

import java.util.Arrays;

public enum MockTableColumns {
	
	ENABLED("Enabled"),
	
	PROTOCOL("Protocol"),
	
	HOST("Host"),
	
	PORT("Port"),
	
	PATH("Path");
	
	private String displayName;
	
	private MockTableColumns(String displayName) {
		this.displayName = displayName;
	}
	
	public static Object[] getDisplayNames() {
		Object[] array = Arrays.stream(MockTableColumns.values()).map(v -> v.displayName).toArray();
		return array;
	}
	
	public static MockTableColumns getByIndex(int index) {
		return MockTableColumns.values()[index];
	}
	
	public static Class<?> getType(int index) {
		if (index == 0) {
			return Boolean.class;
		}
		return String.class;
	}
	

}
