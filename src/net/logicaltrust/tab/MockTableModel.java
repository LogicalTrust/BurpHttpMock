package net.logicaltrust.tab;

import net.logicaltrust.SimpleLogger;
import net.logicaltrust.model.MockEntry;
import net.logicaltrust.model.MockProtocolEnum;
import net.logicaltrust.persistent.MockRepository;

import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableModel;

class MockTableModel extends DefaultTableModel {

    private static final long serialVersionUID = 1L;
    private final SimpleLogger logger;
    private final MockRepository mockHolder;

    public MockTableModel(MockRepository mockHolder, SimpleLogger logger) {
        super(mockHolder.getEntries().stream().map(MockEntry::toObject).toArray(Object[][]::new),
                MockRuleColumnsEnum.getDisplayNames());
        this.mockHolder = mockHolder;
        this.logger = logger;
        this.addTableModelListener(this::handleTableChange);
    }

    @Override
    public void removeRow(int row) {
        logger.debug("Remove row " + row);
        super.removeRow(row);
    }

    private void handleTableChange(TableModelEvent e) {
        logger.debug("ModelTable event " + e.getType() + ", first " + e.getFirstRow() + ", last " + e.getLastRow() + ", column " + e.getColumn());
        if (e.getType() == TableModelEvent.DELETE) {
            handleDeleteAction(mockHolder, e.getFirstRow());
        } else if (e.getType() == TableModelEvent.UPDATE) {
            handleUpdateAction(mockHolder, e);
        }
    }

    private void handleUpdateAction(MockRepository mockHolder, TableModelEvent event) {
        if (event.getFirstRow() != event.getLastRow()) {
            swapEntries(mockHolder, event.getFirstRow(), event.getLastRow());
        } else {
            updateColumn(mockHolder, event.getColumn(), event.getFirstRow());
        }
    }

    private void swapEntries(MockRepository mockHolder, int firstRow, int lastRow) {
        mockHolder.swap(firstRow, lastRow);
    }

    private void updateColumn(MockRepository mockHolder, int columnIndex, int row) {
        MockRuleColumnsEnum column = MockRuleColumnsEnum.getByIndex(columnIndex);
        Object value = this.getValueAt(row, column.ordinal());
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
                mockHolder.update(row, e -> e.getRule().setProtocol((MockProtocolEnum) value));
                break;
            default:
                break;
        }
    }

    private void handleDeleteAction(MockRepository mockHolder, int row) {
        mockHolder.delete(row);
    }

    public void addMock(MockEntry entry) {
        this.addRow(entry.toObject());
        mockHolder.add(entry);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return MockRuleColumnsEnum.getType(columnIndex);
    }

}
