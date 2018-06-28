package net.logicaltrust.mock;

import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

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

	public Optional<Long> findMatch(URL url) {
		return entries.values().stream().filter(e -> e.getRule().matches(url)).map(e -> e.getId()).findAny();
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
		return new ArrayList<>(entries.values());
	}
	
	public synchronized MockEntry getEntry(String id) {
		return entries.get(id);
	}

	public synchronized void update(int row, Consumer<MockRule> updater) {
		MockEntry toEdit = getEntries().get(row);
		updater.accept(toEdit.getRule());
		settingSaver.saveEntry(toEdit);
	}

	public synchronized void delete(int row) {
		MockEntry entry = getEntries().get(row);
		entries.remove(entry.getId() + "");;
		settingSaver.removeEntry(entry.getId());
		settingSaver.saveIdList(getEntries());
	}
	
	public synchronized boolean hasAnyMock() {
		return !entries.isEmpty();
	}

}
