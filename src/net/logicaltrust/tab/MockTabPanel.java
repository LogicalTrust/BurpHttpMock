package net.logicaltrust.tab;

import java.awt.BorderLayout;
import java.awt.Button;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.ITextEditor;
import net.logicaltrust.SimpleLogger;
import net.logicaltrust.editor.ResponseTextEditor;
import net.logicaltrust.mock.MockAdder;
import net.logicaltrust.mock.MockEntry;
import net.logicaltrust.mock.MockHolder;
import net.logicaltrust.mock.MockSettingsSaver;

public class MockTabPanel extends JPanel implements ITab, MockAdder {

	private static final long serialVersionUID = 1L;

	private SimpleLogger logger;
	private IBurpExtenderCallbacks callbacks;
	private MockHolder mockHolder;

	private MockTable mockTable;

	private ResponseTextEditor responseEditor;

	private MockSettingsSaver settingSaver;

	public MockTabPanel(SimpleLogger logger, IBurpExtenderCallbacks callbacks, MockHolder mockHolder, ResponseTextEditor responseEditor, MockSettingsSaver settingSaver) {
		this.logger = logger;
		this.callbacks = callbacks;
		this.mockHolder = mockHolder;
		this.responseEditor = responseEditor;
		this.settingSaver = settingSaver;
		prepareGui(responseEditor);
	}
	
	private void prepareGui(ResponseTextEditor responseEditor) {
		setLayout(new BorderLayout(0, 0));
		prepareGitHubFooter();
		prepareCheckBoxTopPanel();
		
		mockTable = new MockTable("Mock rules", "rules", mockHolder, null, logger, responseEditor);
		JSplitPane pane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, mockTable, responseEditor.getComponent());
		add(pane, BorderLayout.CENTER);
		pane.setResizeWeight(0.3f);
	}

	private void prepareGitHubFooter() {
		JPanel githubPanel = new JPanel();
		githubPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		add(githubPanel, BorderLayout.SOUTH);
		githubPanel.setLayout(new BorderLayout(0, 0));
		
		JLabel githubLabel = createLabelURL("https://github.com/LogicalTrust/???");
		githubPanel.add(githubLabel);
	}

	private void prepareCheckBoxTopPanel() {
		JPanel checkboxPanel = new JPanel();
		add(checkboxPanel, BorderLayout.NORTH);
		checkboxPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
		
		JCheckBox chckbxDebug = new JCheckBox("Debug output");
		chckbxDebug.setSelected(settingSaver.isDebugOn());
		chckbxDebug.addActionListener(e -> { settingSaver.saveDebugOutput(chckbxDebug.isSelected()); });
		checkboxPanel.add(chckbxDebug);
		
		JButton changePort = new JButton("Local port");
		changePort.addActionListener(e -> {
			int initValue = settingSaver.loadPort();
			String input = JOptionPane.showInputDialog("Set port number for local server", initValue + "");
			if (input != null) {
				try {
					int port = Integer.parseInt(input);
					if (port < 1 || port > 65535) {
						JOptionPane.showMessageDialog(this, "Invalid value. Port must be between 1 and 65535", "Invalid value", JOptionPane.ERROR_MESSAGE);
					} else {
						if (port != initValue) {
							settingSaver.savePort(port);
							JOptionPane.showMessageDialog(this, "The change will take effect after restart", "Success", JOptionPane.INFORMATION_MESSAGE);
						}
					} 
				} catch (NumberFormatException e1) {
					JOptionPane.showMessageDialog(this, "Invalid value. Port must be between 1 and 65535", "Invalid value", JOptionPane.ERROR_MESSAGE);
				}
			}
		});
		checkboxPanel.add(changePort);
	}

	private JLabel createLabelURL(String url) {
		JLabel lblUrl = new JLabel(url);
		lblUrl.setForeground(Color.BLUE);
		lblUrl.setCursor(new Cursor(Cursor.HAND_CURSOR));
		lblUrl.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				try {
					Desktop.getDesktop().browse(new URI(lblUrl.getText()));
				} catch (URISyntaxException | IOException ex) {
					ex.printStackTrace(logger.getStderr());
				}
			}
		});
		return lblUrl;
	}

	@Override
	public String getTabCaption() {
		return "Mock";
	}

	@Override
	public Component getUiComponent() {
		return this;
	}

	@Override
	public void addMock(MockEntry entry) {
		mockTable.addMock(entry);
	}

}
