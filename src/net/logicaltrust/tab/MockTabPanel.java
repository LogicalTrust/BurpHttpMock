package net.logicaltrust.tab;

import java.awt.BorderLayout;
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
import java.util.ArrayList;
import java.util.List;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import net.logicaltrust.SimpleLogger;
import net.logicaltrust.mock.MockHolder;

public class MockTabPanel extends JPanel implements ITab {

	private static final long serialVersionUID = 1L;

	private SimpleLogger logger;
	private IBurpExtenderCallbacks callbacks;
	private MockHolder mockHolder;

	public MockTabPanel(SimpleLogger logger, IBurpExtenderCallbacks callbacks, MockHolder mockHolder) {
		this.logger = logger;
		this.callbacks = callbacks;
		this.mockHolder = mockHolder;
		prepareGui();
	}
	
	private void prepareGui() {
		setLayout(new BorderLayout(0, 0));
		
		JPanel githubPanel = new JPanel();
		githubPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		add(githubPanel, BorderLayout.SOUTH);
		githubPanel.setLayout(new BorderLayout(0, 0));
		
		JLabel githubLabel = createLabelURL("https://github.com/LogicalTrust/???");
		githubPanel.add(githubLabel);
		
		
		
		JPanel checkboxPanel = new JPanel();
		add(checkboxPanel, BorderLayout.NORTH);
		checkboxPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
		
		JCheckBox chckbxDebug = new JCheckBox("Debug output");
		chckbxDebug.addActionListener(e -> { logger.debug(e + ""); });
		checkboxPanel.add(chckbxDebug);
		
		
		
		JPanel tablesPanel = new JPanel();
		add(tablesPanel, BorderLayout.CENTER);
		tablesPanel.setLayout(new GridLayout(0, 2, 0, 0));
		
		MockTable mockTable = new MockTable("Mock rules", "rules", mockHolder, null, logger);
		tablesPanel.add(mockTable);
		
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

}
