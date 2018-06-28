package net.logicaltrust.mock;

import java.net.URL;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class MockHolder {

	private Map<String, MockEntry> entries = new LinkedHashMap<>();
	private long counter = 0L;
	private MockSettingsSaver settingSaver;

	public MockHolder(List<MockEntry> loadedEntries, MockSettingsSaver settingSaver) {
		this.settingSaver = settingSaver;
		for (MockEntry e : loadedEntries) {
			entries.put(e.getId() + "", e);
		}
		long maxId = loadedEntries.get(loadedEntries.size() - 1).getId();
		counter = maxId + 1;
	}

	public String findMatch(URL url) {
		for (Entry<String, MockEntry> e : entries.entrySet()) {
			MockRule rule = e.getValue().getRule();
			if (rule.matches(url)) {
				return e.getKey();
			}
		}
		return null;
	}

	public synchronized void add(MockEntry entry) {
		long id = counter;
		entry.setId(id);
		counter++;
		entries.put(id + "", entry);
		settingSaver.saveEntry(entry);
		settingSaver.saveIdList(getEntries());
	}

	public List<MockEntry> getEntries() {
		return entries.entrySet().stream().map(e -> e.getValue()).collect(Collectors.toList());
	}

	public synchronized byte[] getResponse(String id) {
		MockEntry mockEntry = entries.get(id);
		return mockEntry.getResponse();
	}

	public synchronized void update(int row, Consumer<MockRule> updater) {
		MockEntry toEdit = getEntries().get(row);
		updater.accept(toEdit.getRule());
		settingSaver.saveEntry(toEdit);
	}

	public synchronized void delete(int row) {
		MockEntry entry = getEntries().get(row);
		entries.remove(entry.getId() + "");
		settingSaver.removeEntry(entry.getId());
		settingSaver.saveIdList(getEntries());
	}
	
	public synchronized boolean hasAnyMock() {
		return entries.isEmpty();
	}

}
