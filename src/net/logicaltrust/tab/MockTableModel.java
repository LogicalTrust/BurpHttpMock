package net.logicaltrust.tab;

import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableModel;

import net.logicaltrust.SimpleLogger;
import net.logicaltrust.mock.MockEntry;
import net.logicaltrust.mock.MockHolder;
import net.logicaltrust.mock.MockRule;

public class MockTableModel extends DefaultTableModel {

	private static final long serialVersionUID = 1L;
	@SuppressWarnings("unused")
	private SimpleLogger logger;

	public MockTableModel(MockHolder mockHolder, SimpleLogger logger) {
		super(mockHolder.getEntries().stream().map(v -> v.getRule()).map(v -> new Object[] { true, v.getProtocol(), v.getHost(), v.getPort(), v.getPath() }).toArray(Object[][]::new), MockTableColumns.getDisplayNames());
		this.logger = logger;
		this.addTableModelListener(e -> {
			int row = e.getFirstRow();
			if (e.getType() == TableModelEvent.INSERT) {
				handleInsertAction(mockHolder, logger, e, row);
			} else if (e.getType() == TableModelEvent.DELETE) {
				handleDeleteAction(mockHolder, row);
			} else if (e.getType() == TableModelEvent.UPDATE) {
				handleUpdateAction(mockHolder, e, row);
			}
		});
	}

	private void handleUpdateAction(MockHolder mockHolder, TableModelEvent e, int row) {
		MockTableColumns column = MockTableColumns.getByIndex(e.getColumn());
		Object value = this.getValueAt(row, column.ordinal());
		switch (column) {
		case ENABLED:
			break;	 
		case HOST:
			mockHolder.update(row, r -> r.setHost((String)value));
			break;
		case PATH:
			mockHolder.update(row, r -> r.setPath((String)value));
			break;
		case PORT:
			mockHolder.update(row, r -> r.setPort((String)value));
			break;
		case PROTOCOL:
			mockHolder.update(row, r -> r.setProtocol((String)value));
			break;
		default:
			break;
		}
	}

	private void handleDeleteAction(MockHolder mockHolder, int row) {
		mockHolder.delete(row);
	}

	private void handleInsertAction(MockHolder mockHolder, SimpleLogger logger, TableModelEvent e, int row) {
		logger.debug(row + " " + e.getColumn());
		MockRule rule = new MockRule(this.getValue(row, MockTableColumns.PROTOCOL),
				this.getValue(row, MockTableColumns.HOST),
				this.getValue(row, MockTableColumns.PORT),
				this.getValue(row, MockTableColumns.PATH));
		MockEntry entry = new MockEntry(rule, new byte[0]);
		mockHolder.add(entry);
	}
	
	private String getValue(int row, MockTableColumns column) {
		return (String) this.getValueAt(row, column.ordinal());
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return MockTableColumns.getType(columnIndex);
	}

}
