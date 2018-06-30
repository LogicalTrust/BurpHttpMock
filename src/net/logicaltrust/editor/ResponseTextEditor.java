package net.logicaltrust.editor;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JPanel;

import burp.IExtensionHelpers;
import burp.ITextEditor;
import net.logicaltrust.SimpleLogger;
import net.logicaltrust.mock.MockEntry;
import net.logicaltrust.mock.MockHolder;

public class ResponseTextEditor {

	private ITextEditor textEditor;
	private JPanel mainPanel;
	private JButton saveTextButton;
	private JButton discardTextButton;
	private JCheckBox recalcBox;
	
	private MockEntry currentEntry;
	private SimpleLogger logger;
	private MockHolder mockHolder;

	public ResponseTextEditor(SimpleLogger logger, ITextEditor textEditor, MockHolder mockHolder, IExtensionHelpers helpers) {
		this.logger = logger;
		this.textEditor = textEditor;
		this.mockHolder = mockHolder;
		this.textEditor.setEditable(false);
		mainPanel = new JPanel();
		mainPanel.setLayout(new BorderLayout());
		JPanel textButtonPanel = new JPanel();
		textButtonPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
		saveTextButton = new JButton("Save");
		discardTextButton = new JButton("Discard");
		recalcBox = new JCheckBox("Recalculate Content-Length");
		textButtonPanel.add(saveTextButton);
		textButtonPanel.add(discardTextButton);
		textButtonPanel.add(recalcBox);
		
		mainPanel.add(textEditor.getComponent());
		mainPanel.add(textButtonPanel, BorderLayout.SOUTH);
		
		saveTextButton.addActionListener(e -> saveChanges());
		
		discardTextButton.addActionListener(e -> {
			logger.debug("Message discarded");
			if (textEditor.isTextModified()) {
				textEditor.setText(currentEntry.getResponse());
			}
		});
	}
	
	public void saveChanges() {
		if (textEditor.isTextModified()) {
			byte[] text = textEditor.getText();
			if (recalcBox.isSelected()) {
				logger.debug("Recalculating content length");
				text = recalculateContentLength(text);
			}
			mockHolder.updateResponse(currentEntry.getId()+"", text);
			loadResponse(currentEntry);
		}
	}

	private byte[] recalculateContentLength(byte[] text) {
		return text;
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
