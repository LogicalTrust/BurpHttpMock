package net.logicaltrust.persistent;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import net.logicaltrust.SimpleLogger;
import net.logicaltrust.model.MockEntry;
import net.logicaltrust.model.MockProtocolEnum;
import net.logicaltrust.model.MockRule;

public class MockRepository {

	private Map<String, MockEntry> entriesById = new HashMap<>();
	private LinkedList<MockEntry> entries = new LinkedList<>();
	private long counter = 0L;
	private SettingsSaver settingSaver;
	private SimpleLogger logger;
	
	public MockRepository(SimpleLogger logger, SettingsSaver settingSaver) {
		this.logger = logger;
		this.settingSaver = settingSaver;
		List<MockEntry> loadedEntries = settingSaver.loadEntries();
		int i = 0;
		long maxId = 0;
		for (MockEntry e : loadedEntries) {
			entriesById.put(e.getId() + "", e);
			entries.add(e);
			logger.debug("Index: " + i++ + ", ID: " + e.getId() + ", URL: " + e.getRule());
			maxId = Math.max(maxId, e.getId());
		}
		logger.debug("Calculated max id: " + maxId);
		counter = maxId + 1;
	}

	public synchronized Optional<MockEntry> findMatch(URL url) {
		return entries.stream()
				.filter(MockEntry::isEnabled)
				.filter(e -> e.getRule().matches(url))
				.findAny();
	}

	public synchronized void add(MockEntry entry) {
		long id = counter++;
		entry.setId(id);
		entriesById.put(id + "", entry);
		entries.add(entry);
		settingSaver.saveEntry(entry);
		settingSaver.saveIdList(getEntries());
	}

	public synchronized List<MockEntry> getEntries() {
		return entries;
	}
	
	public synchronized MockEntry getEntryById(String id) {
		return entriesById.get(id);
	}
	
	public synchronized MockEntry getEntryByIndex(int row) {
		return entries.get(row);
	}

	public synchronized List<MockEntry> getEntriesByIndexArray(int[] rows) {
		List<MockEntry> result = new ArrayList<>(rows.length);
		for (int row : rows) {
			result.add(entries.get(row));
		}
		return result;
	}

	public synchronized void update(int row, Consumer<MockEntry> updater) {
		MockEntry toEdit = getEntries().get(row);
		updater.accept(toEdit);
		settingSaver.saveEntry(toEdit);
	}
	
	public synchronized void delete(int row) {
		MockEntry entry = entries.remove(row);
		entriesById.remove(entry.getId() + "");
		settingSaver.removeEntry(entry.getId());
		settingSaver.saveIdList(getEntries());
	}
	
	public synchronized boolean hasAnyMock() {
		return !entriesById.isEmpty();
	}
	
	public synchronized void updateResponse(String id, byte[] response) {
		MockEntry entry = entriesById.get(id);
		entry.setResponse(response);
		logger.debug("Updating " + entry + ", " + id);
		settingSaver.saveEntry(entry);
	}
	
	public synchronized void swap(int first, int second) {
		Collections.swap(entries, first, second);
		settingSaver.saveIdList(getEntries());
	}

}
