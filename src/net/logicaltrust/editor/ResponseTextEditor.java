package net.logicaltrust.editor;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.util.Optional;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JPanel;

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

	public ResponseTextEditor(SimpleLogger logger, ITextEditor textEditor, MockHolder mockHolder) {
		this.textEditor = textEditor;
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
		
		saveTextButton.addActionListener(e -> {
			logger.debug("Message modified: " + textEditor.isTextModified());
			if (textEditor.isTextModified()) {
				mockHolder.updateResponse(currentEntry.getId()+"", textEditor.getText());
			}
		});
	}

	public void loadResponse(MockEntry entry) {
		this.currentEntry = entry;
		this.textEditor.setEditable(true);
		this.textEditor.setText(entry.getResponse());
	}
	
	public Component getComponent() {
		return mainPanel;
	}
	
	
	
	
	
}
