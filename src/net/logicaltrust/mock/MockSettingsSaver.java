package net.logicaltrust.mock;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import burp.IBurpExtenderCallbacks;
import net.logicaltrust.SimpleLogger;

public class MockSettingsSaver {
	
	private static final String ID_LIST = "ID_LIST";
	private IBurpExtenderCallbacks callbacks;
	private static final String DELIM = "|";
	private static final String DELIM_REGEX = "\\|";
	private SimpleLogger logger;
	
	public MockSettingsSaver(IBurpExtenderCallbacks callbacks, SimpleLogger logger) {
		this.callbacks = callbacks;
		this.logger = logger;
	}
	
	public void clear() {
		String strIds = callbacks.loadExtensionSetting(ID_LIST);
		Arrays.stream(strIds.split(DELIM_REGEX)).forEach(id -> {
			callbacks.saveExtensionSetting("ENTRY_" + id, null);
		});
		callbacks.saveExtensionSetting(ID_LIST, null);
	}
	
	public void saveEntry(MockEntry entry) {
		logger.debug("Saving entry " + entry.getId());
		callbacks.saveExtensionSetting("ENTRY_" + entry.getId(), entryToString(entry));
	}
	
	public void removeEntry(long id) {
		logger.debug("Removing entry " + id);
		callbacks.saveExtensionSetting("ENTRY_" + id, null);
	}
	
	public void saveIdList(Collection<MockEntry> entries) {
		String ids = entries.stream().map(e -> e.getId()).map(e -> e.toString()).collect(Collectors.joining(DELIM, "", ""));
		logger.debug("Saving entry list " + ids);
		callbacks.saveExtensionSetting(ID_LIST, ids);
	}
	
	public List<MockEntry> loadEntries() {
		logger.debug("Loading entries");
		String strIds = callbacks.loadExtensionSetting(ID_LIST);
		if (strIds == null) {
			return new ArrayList<>();
		}
		List<MockEntry> entries = Arrays.stream(strIds.split(DELIM_REGEX)).map(id -> {
			String entryStr = callbacks.loadExtensionSetting("ENTRY_"+ id);
			MockEntry entry = entryFromString(entryStr, id);
			return entry;
		}).collect(Collectors.toList());
		logger.debug(entries.isEmpty() ? "No entries loaded" : "Loaded " + entries.size() + " entries");
		return entries;
	}
	
	private MockEntry entryFromString(String str, String id) {
		String[] split = str.split(DELIM_REGEX);
		
		if (split.length != 5 && split.length != 4) {
			//error
		}
		
		byte[] response = split.length == 5 ? decode(split[4]) : new byte[0];
		
		MockRule rule = new MockRule(decodeToString(split[0]), 
				decodeToString(split[1]), 
				decodeToString(split[2]), 
				decodeToString(split[3]));
		MockEntry entry = new MockEntry(rule, response);
		entry.setId(Long.parseLong(id));
		return entry;
	}
	
	private String entryToString(MockEntry entry) {
		MockRule rule = entry.getRule();
		StringBuilder result = new StringBuilder();
		result.append(encode(rule.getProtocol())).append(DELIM)
		.append(encode(rule.getHost())).append(DELIM)
		.append(encode(rule.getPort()+"")).append(DELIM)
		.append(encode(rule.getPath())).append(DELIM)
		.append(encode(entry.getResponse()));
		return result.toString();
	}
	
	private byte[] decode(String encoded) {
		return Base64.getDecoder().decode(encoded);
	}
	
	private String decodeToString(String encoded) {
		return new String(decode(encoded), StandardCharsets.UTF_8);
	}
	
	private String encode(byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}
	
	private String encode(String element) {
		return encode(element.getBytes(StandardCharsets.UTF_8));
	}

}
