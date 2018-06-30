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
import net.logicaltrust.tab.MockProtocolEnum;

public class MockSettingsSaver {
	
	private static final String ID_LIST = "ID_LIST";
	private static final String RECALCULATE_CONTENT_LENGTH = "RECALCULATE_CONTENT_LENGTH";
	private static final String DEBUG_OUTPUT = "DEBUG_OUTPUT";
	private IBurpExtenderCallbacks callbacks;
	private static final String DELIM = "|";
	private static final String DELIM_REGEX = "\\|";
	private SimpleLogger logger;
	
	private static final int ENTRY_PARAMS = 6;
	
	public MockSettingsSaver(IBurpExtenderCallbacks callbacks, SimpleLogger logger) {
		this.callbacks = callbacks;
		this.logger = logger;
		if (isDebugOn()) {
			logger.enableDebug();
		} else {
			logger.disableDebug();
		}
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
		String ids = entries.stream()
				.map(e -> e.getId())
				.map(e -> e.toString())
				.collect(Collectors.joining(DELIM, "", ""));
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
	
	public void saveRecalculateContentLength(boolean recalc) {
		callbacks.saveExtensionSetting(RECALCULATE_CONTENT_LENGTH, Boolean.toString(recalc));
	}
	
	public boolean loadRecalculateContentLength() {
		String value = callbacks.loadExtensionSetting(RECALCULATE_CONTENT_LENGTH);
		return value == null ? true : Boolean.parseBoolean(value);
	}
	
	public void saveDebugOutput(boolean debug) {
		callbacks.saveExtensionSetting(DEBUG_OUTPUT, Boolean.toString(debug));
		if (debug) {
			logger.enableDebug();
		} else {
			logger.disableDebug();
		}
	}
	
	public boolean isDebugOn() {
		return Boolean.parseBoolean(callbacks.loadExtensionSetting(DEBUG_OUTPUT));
	}
	
	private MockEntry entryFromString(String str, String id) {
		String[] split = str.split(DELIM_REGEX);
		
		if (split.length != ENTRY_PARAMS) {
			logger.debugForce("Invalid entry, id: " + id +", value: " + Arrays.toString(split));
		}
		
		byte[] response = decode(split[5]);
		MockRule rule = new MockRule(MockProtocolEnum.valueOf(decodeToString(split[1])), 
				decodeToString(split[2]), 
				decodeToString(split[3]), 
				decodeToString(split[4]));
		MockEntry entry = new MockEntry(Boolean.parseBoolean(split[0]), rule, response);
		entry.setId(Long.parseLong(id));
		return entry;
	}
	
	private String entryToString(MockEntry entry) {
		MockRule rule = entry.getRule();
		StringBuilder result = new StringBuilder();
		result.append(entry.isEnabled()).append(DELIM)
		.append(encode(rule.getProtocol().name())).append(DELIM)
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
