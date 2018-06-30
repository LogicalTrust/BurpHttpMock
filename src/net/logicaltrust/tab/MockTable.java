package net.logicaltrust.tab;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.util.Collection;
import java.util.function.Consumer;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;

import net.logicaltrust.SimpleLogger;
import net.logicaltrust.editor.ResponseTextEditor;
import net.logicaltrust.mock.MockEntry;
import net.logicaltrust.mock.MockHolder;
import net.logicaltrust.mock.MockRule;

public class MockTable extends JPanel {

	private static final long serialVersionUID = 1L;
	private MockTableModel model;
	private ResponseTextEditor responseTextEditor;
	int previousRow = -1;

	public MockTable(String title, String tooltip, MockHolder mockHolder, 
			Consumer<Collection<String>> updateValues, SimpleLogger logger, ResponseTextEditor responseTextEditor) {
		
		this.responseTextEditor = responseTextEditor;
		this.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0)), title, TitledBorder.LEADING, TitledBorder.TOP, null, null));
		this.setToolTipText(tooltip);
		this.setLayout(new BorderLayout(0, 0));
		
		model = new MockTableModel(mockHolder, logger);
		
		JPanel buttonPanel = new JPanel();
		this.add(buttonPanel, BorderLayout.WEST);
		GridBagLayout buttonPanelLayout = new GridBagLayout();
		buttonPanelLayout.columnWidths = new int[] {50};
		buttonPanelLayout.rowHeights = new int[] {0, 0, 0, 25};
		buttonPanelLayout.columnWeights = new double[]{0.0};
		buttonPanelLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		buttonPanel.setLayout(buttonPanelLayout);
		
		JButton addButton = new JButton("Add");
		buttonPanel.add(addButton, createTableButtonConstraints(0));
		
		JButton deleteButton = new JButton("Delete");
		buttonPanel.add(deleteButton, createTableButtonConstraints(1));
		
		JButton pasteUrlButton = new JButton("Paste URL");
		buttonPanel.add(pasteUrlButton, createTableButtonConstraints(2));
		
		JTable table = new JTable();
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		this.add(table, BorderLayout.CENTER);
		table.setModel(model);
		
		JScrollPane scroll = new JScrollPane(table);
		scroll.setVisible(true);
		this.add(scroll);
		
		deleteButton.addActionListener(e -> {
			int selectedRow = table.getSelectedRow();
			if (selectedRow != -1) {
				model.removeRow(selectedRow);
			}
		});
		
		addButton.addActionListener(e -> {
			JTextField proto = new JTextField();
			JTextField host = new JTextField();
			JTextField port = new JTextField();
			JTextField file = new JTextField();
			Object[] msg = new Object[] { "Proto", proto, "Host", host, "Port", port, "File", file };
			int result = JOptionPane.showConfirmDialog(null, msg, "Add mock", JOptionPane.OK_CANCEL_OPTION);
			if (result == JOptionPane.OK_OPTION) {
				MockRule rule = new MockRule(proto.getText(), host.getText(), port.getText(), file.getText());
				MockEntry entry = new MockEntry(rule, new byte[0]);
				model.addMock(entry);
			}
		});
		
		ListSelectionModel selectionModel = table.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(e -> {
			int row = table.getSelectedRow();
			logger.debug("Selection changed, from: " + previousRow + " to :" + row);
			if (row != previousRow) {
				boolean cancel = false;
				if (responseTextEditor.hasUnsavedChanges()) {
					int result = JOptionPane.showConfirmDialog(null, "Do you want to save before leave?", "Changes not saved", JOptionPane.YES_NO_CANCEL_OPTION);
					if (result == JOptionPane.YES_OPTION) {
						responseTextEditor.saveChanges();
						previousRow = row;
					} else if (result == JOptionPane.NO_OPTION) {
						//discard
						previousRow = row;
					} else {
						//go back
						table.setRowSelectionInterval(previousRow, previousRow);
						cancel = true;
					}
				}
				
				if (!cancel) {
					previousRow = row;
					MockEntry entry = mockHolder.getEntry(row);
					logger.debug("Selected row: " + row +", entry: " + entry.getId() + ", " + entry.getRule());
					responseTextEditor.loadResponse(entry);
				}
			}
		});
	}

	private GridBagConstraints createTableButtonConstraints(int index) {
		GridBagConstraints btnConstraints = new GridBagConstraints();
		btnConstraints.fill = GridBagConstraints.HORIZONTAL;
		btnConstraints.anchor = GridBagConstraints.NORTH;
		btnConstraints.gridx = 0;
		btnConstraints.gridy = index;
		return btnConstraints;
	}

	public void addMock(MockEntry entry) {
		model.addMock(entry);
	}

}
