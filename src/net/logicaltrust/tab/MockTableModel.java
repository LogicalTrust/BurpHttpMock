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
	private MockHolder mockHolder;

	public MockTableModel(MockHolder mockHolder, SimpleLogger logger) {
		super(mockHolder.getEntries().stream().map(v -> v.getRule()).map(v -> new Object[] { true, v.getProtocol(), v.getHost(), v.getPort(), v.getPath() }).toArray(Object[][]::new), MockTableColumns.getDisplayNames());
		this.mockHolder = mockHolder;
		this.logger = logger;
		this.addTableModelListener(e -> {
			int row = e.getFirstRow();
			if (e.getType() == TableModelEvent.INSERT) {
				//ignore
			} else if (e.getType() == TableModelEvent.DELETE) {
				handleDeleteAction(mockHolder, row);
			} else if (e.getType() == TableModelEvent.UPDATE) {
				handleUpdateAction(mockHolder, e, row);
			}
		});
	}

	private void handleUpdateAction(MockHolder mockHolder, TableModelEvent event, int row) {
		MockTableColumns column = MockTableColumns.getByIndex(event.getColumn());
		Object value = this.getValueAt(row, column.ordinal());
		logger.debug("Update: " + value);
		switch (column) {
		case ENABLED:
			mockHolder.update(row, e -> e.setEnabled((boolean) value));
			break;	 
		case HOST:
			mockHolder.update(row, e -> e.getRule().setHost((String) value));
			break;
		case PATH:
			mockHolder.update(row, e -> e.getRule().setPath((String) value));
			break;
		case PORT:
			mockHolder.update(row, e -> e.getRule().setPort((String) value));
			break;
		case PROTOCOL:
			mockHolder.update(row, e -> e.getRule().setProtocol((String) value));
			break;
		default:
			break;
		}
	}

	private void handleDeleteAction(MockHolder mockHolder, int row) {
		mockHolder.delete(row);
	}

	public void addMock(MockEntry entry) {
		MockRule rule = entry.getRule();
		Object[] row = new Object[] { true, rule.getProtocol(), rule.getHost(), rule.getPort(), rule.getPath() };
		this.addRow(row);
		mockHolder.add(entry);
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return MockTableColumns.getType(columnIndex);
	}

}
