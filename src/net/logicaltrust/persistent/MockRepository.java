package net.logicaltrust.persistent;

import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import net.logicaltrust.SimpleLogger;
import net.logicaltrust.model.MockEntry;

public class MockRepository {

	private Map<String, MockEntry> entries = new LinkedHashMap<>();
	private long counter = 0L;
	private SettingsSaver settingSaver;
	private SimpleLogger logger;
	
	public MockRepository(SimpleLogger logger, SettingsSaver settingSaver) {
		this.logger = logger;
		this.settingSaver = settingSaver;
		List<MockEntry> loadedEntries = settingSaver.loadEntries();
		int i = 0;
		for (MockEntry e : loadedEntries) {
			entries.put(e.getId() + "", e);
			logger.debug("Index: " + i++ + ", ID: " + e.getId() + ", URL: " + e.getRule());
		}
		long maxId = loadedEntries.get(loadedEntries.size() - 1).getId();
		logger.debug("Calculated max id: " + maxId);
		counter = maxId + 1;
	}

	public Optional<MockEntry> findMatch(URL url) {
		return entries.values().stream()
				.filter(e -> e.isEnabled())
				.filter(e -> e.getRule().matches(url))
				.findAny();
	}

	public synchronized void add(MockEntry entry) {
		long id = counter++;
		entry.setId(id);
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
	
	public synchronized MockEntry getEntry(int row) {
		return getEntries().get(row);
	}

	public synchronized void update(int row, Consumer<MockEntry> updater) {
		MockEntry toEdit = getEntries().get(row);
		updater.accept(toEdit);
		settingSaver.saveEntry(toEdit);
	}
	
	public synchronized void delete(int row) {
		MockEntry entry = getEntry(row);
		entries.remove(entry.getId() + "");;
		settingSaver.removeEntry(entry.getId());
		settingSaver.saveIdList(getEntries());
	}
	
	public synchronized boolean hasAnyMock() {
		return !entries.isEmpty();
	}
	
	public void updateResponse(String id, byte[] response) {
		MockEntry entry = entries.get(id);
		entry.setResponse(response);
		logger.debug("Updating " + entry + ", " + id);
		settingSaver.saveEntry(entry);
	}

}
