package net.logicaltrust.editor;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

import burp.IExtensionHelpers;
import burp.IResponseInfo;
import burp.ITextEditor;
import net.logicaltrust.SimpleLogger;
import net.logicaltrust.model.MockEntry;
import net.logicaltrust.persistent.MockRepository;
import net.logicaltrust.persistent.SettingsSaver;

public class ResponseTextEditor {

	private ITextEditor textEditor;
	private JPanel mainPanel;
	private JButton saveTextButton;
	private JButton discardTextButton;
	private JCheckBox recalcBox;
	
	private MockEntry currentEntry;
	private SimpleLogger logger;
	private MockRepository mockHolder;
	private IExtensionHelpers helpers;
	
	private static final Pattern CONTENT_LENGTH_PATTERN = Pattern.compile("^Content-Length: .*$", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);

	public ResponseTextEditor(SimpleLogger logger, ITextEditor textEditor, MockRepository mockHolder, IExtensionHelpers helpers, SettingsSaver settingSaver) {
		this.logger = logger;
		this.textEditor = textEditor;
		this.mockHolder = mockHolder;
		this.helpers = helpers;
		this.textEditor.setEditable(false);
		
		mainPanel = new JPanel();
		mainPanel.setBorder(new TitledBorder(new EmptyBorder(0, 0, 0, 0), "Response editor", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		mainPanel.setLayout(new BorderLayout());

		JPanel textButtonPanel = new JPanel();
		textButtonPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
		
		saveTextButton = new JButton("Save");
		discardTextButton = new JButton("Discard");
		recalcBox = new JCheckBox("Recalculate Content-Length");
		recalcBox.setSelected(settingSaver.loadRecalculateContentLength());
		
		textButtonPanel.add(saveTextButton);
		textButtonPanel.add(discardTextButton);
		textButtonPanel.add(recalcBox);
		
		JPanel textEditorPanel = new JPanel();
		textEditorPanel.setLayout(new BorderLayout());
		textEditorPanel.setBorder(new EmptyBorder(5, 0, 0, 0));
		textEditorPanel.add(textEditor.getComponent());
		mainPanel.add(textEditorPanel);
		mainPanel.add(textButtonPanel, BorderLayout.SOUTH);
		
		saveTextButton.addActionListener(e -> saveChanges());
		discardTextButton.addActionListener(e -> discardChanges());
		recalcBox.addActionListener(e -> settingSaver.saveRecalculateContentLength(recalcBox.isSelected()));
	}

	private void discardChanges() {
		logger.debug("Message discarded");
		if (textEditor.isTextModified()) {
			textEditor.setText(currentEntry.getResponse());
		}
	}
	
	public void saveChanges() {
		byte[] text = textEditor.getText();
		if (recalcBox.isSelected()) {
			logger.debug("Recalculating content length");
			text = recalculateContentLength(text);
		}
		mockHolder.updateResponse(currentEntry.getId()+"", text);
		loadResponse(currentEntry);
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
		this.textEditor.setEditable(true);
		this.textEditor.setText(entry.getResponse());
	}
	
	public boolean hasUnsavedChanges() {
		return currentEntry != null && textEditor.isTextModified();
	}
	
	public Component getComponent() {
		return mainPanel;
	}
	
}
