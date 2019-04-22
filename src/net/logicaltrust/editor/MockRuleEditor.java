package net.logicaltrust.editor;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IResponseInfo;
import burp.ITextEditor;
import net.logicaltrust.SimpleLogger;
import net.logicaltrust.model.MockEntry;
import net.logicaltrust.model.MockEntryTypeEnum;
import net.logicaltrust.persistent.MockRepository;
import net.logicaltrust.persistent.SettingsSaver;

public class MockRuleEditor {

	private final ITextEditor textEditor;
	private final JPanel mainPanel;
	private final JButton saveEntryButton;
	private final JButton discardChangesButton;
	private final JButton browseButton;
	private final JComboBox<MockEntryTypeEnum> entryTypeComboBox;
	private final JCheckBox recalcBox;
	
	private MockEntry currentEntry;
	private final SimpleLogger logger;
	private final MockRepository mockHolder;
	private final IExtensionHelpers helpers;
	private final SettingsSaver settingSaver;

	private static final Pattern CONTENT_LENGTH_PATTERN = Pattern.compile("^Content-Length: .*$", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);

	public MockRuleEditor(ITextEditor textEditor, MockRepository mockHolder, SettingsSaver settingSaver) {
		this.logger = BurpExtender.getLogger();
		this.textEditor = textEditor;
		this.mockHolder = mockHolder;
		this.helpers = BurpExtender.getCallbacks().getHelpers();
		this.settingSaver = settingSaver;
		this.textEditor.setEditable(false);
		
		mainPanel = new JPanel();
		mainPanel.setBorder(new TitledBorder(new EmptyBorder(0, 0, 0, 0), "Response editor", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		mainPanel.setLayout(new BorderLayout());

		JPanel saveOptionsPanel = new JPanel();
		saveOptionsPanel.setLayout(new FlowLayout(FlowLayout.RIGHT, 5, 5));
		
		saveEntryButton = new JButton("Save");
		discardChangesButton = new JButton("Discard");
		recalcBox = new JCheckBox("Recalculate Content-Length");
		recalcBox.setSelected(settingSaver.loadRecalculateContentLength());
		
		saveOptionsPanel.add(saveEntryButton);
		saveOptionsPanel.add(discardChangesButton);
		saveOptionsPanel.add(recalcBox);

		JPanel ruleOptionsPanel = new JPanel();
		ruleOptionsPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
		entryTypeComboBox = new JComboBox<>(MockEntryTypeEnum.values());
		browseButton = new JButton("Insert Path");
		browseButton.addActionListener(e -> insertPath());
		ruleOptionsPanel.add(entryTypeComboBox);
		ruleOptionsPanel.add(browseButton);

		JPanel bottomPanel = new JPanel();
		bottomPanel.setLayout(new BorderLayout());
		bottomPanel.add(ruleOptionsPanel, BorderLayout.WEST);
		bottomPanel.add(saveOptionsPanel, BorderLayout.EAST);

		JPanel textEditorPanel = new JPanel();
		textEditorPanel.setLayout(new BorderLayout());
		textEditorPanel.setBorder(new EmptyBorder(5, 0, 0, 0));
		textEditorPanel.add(textEditor.getComponent());
		mainPanel.add(textEditorPanel);
		mainPanel.add(bottomPanel, BorderLayout.SOUTH);
		
		saveEntryButton.addActionListener(e -> saveChanges());
		discardChangesButton.addActionListener(e -> discardChanges());
		recalcBox.addActionListener(e -> settingSaver.saveRecalculateContentLength(recalcBox.isSelected()));
	}

	public void discardChanges() {
		logger.debug("Message discarded");
		if (textEditor.isTextModified()) {
			textEditor.setText(currentEntry.getEntryInput());
			entryTypeComboBox.setSelectedItem(currentEntry.getEntryType());
		}
	}
	
	public void saveChanges() {
		byte[] text = textEditor.getText();
		if (recalcBox.isSelected()) {
			logger.debug("Recalculating content length");
			text = recalculateContentLength(text);
		}
		mockHolder.updateResponse(currentEntry.getId()+"", text,
				(MockEntryTypeEnum) entryTypeComboBox.getSelectedItem());
		loadResponse(currentEntry);
	}

	private void insertPath()
	{
		JFileChooser chooser = new JFileChooser();
		chooser.setDialogTitle("Choose a file to insert as a path");
		chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
		if (chooser.showOpenDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
			IExtensionHelpers helpers = BurpExtender.getCallbacks().getHelpers();
			textEditor.setText(helpers.stringToBytes(helpers.bytesToString(textEditor.getText()) +
					"\"" + chooser.getSelectedFile().getPath() + "\""));
		}
	}

	private byte[] recalculateContentLength(byte[] text) {
		IResponseInfo response = helpers.analyzeResponse(text);
		int contentLength = text.length - response.getBodyOffset();
		String responseStr = new String(text, StandardCharsets.UTF_8);
		Matcher matcher = CONTENT_LENGTH_PATTERN.matcher(responseStr);
		String replaced = matcher.replaceFirst("Content-Length: " + contentLength);
		return replaced.getBytes(StandardCharsets.UTF_8);
	}

	public void loadResponse(MockEntry entry) {
		this.currentEntry = entry;
		this.entryTypeComboBox.setEnabled(true);
		this.entryTypeComboBox.setSelectedItem(entry.getEntryType());
		this.browseButton.setEnabled(true);
		if (!settingSaver.loadDisplayLargeResponsesInEditor() && entry.getEntryInput().length > settingSaver.loadThreshold()) {
			this.textEditor.setEditable(false);
			this.textEditor.setText("Response is too large.".getBytes(StandardCharsets.UTF_8));
		} else {
			this.textEditor.setEditable(true);
			this.textEditor.setText(entry.getEntryInput());
		}
		this.saveEntryButton.setEnabled(true);
		this.discardChangesButton.setEnabled(true);
		this.recalcBox.setEnabled(true);
	}
	
	public void unloadResponse() {
		this.currentEntry = null;
		this.textEditor.setEditable(false);
		this.textEditor.setText(null);
		this.browseButton.setEnabled(false);
		this.entryTypeComboBox.setEnabled(false);
		this.entryTypeComboBox.setSelectedItem(null);
		this.saveEntryButton.setEnabled(false);
		this.discardChangesButton.setEnabled(false);
		this.recalcBox.setEnabled(false);
	}
	
	public boolean hasUnsavedChanges() {
		return currentEntry != null &&
				(textEditor.isTextModified() || entryTypeComboBox.getSelectedItem() != currentEntry.getEntryType());
	}
	
	public Component getComponent() {
		return mainPanel;
	}
	
}
