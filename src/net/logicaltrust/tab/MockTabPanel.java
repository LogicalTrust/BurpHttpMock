package net.logicaltrust.tab;

import burp.BurpExtender;
import burp.ITab;
import net.logicaltrust.SimpleLogger;
import net.logicaltrust.editor.MockRuleEditor;
import net.logicaltrust.model.MockEntry;
import net.logicaltrust.persistent.MockAdder;
import net.logicaltrust.persistent.MockRepository;
import net.logicaltrust.persistent.SettingsSaver;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

public class MockTabPanel extends JPanel implements ITab, MockAdder {

    private static final long serialVersionUID = 1L;

    private final SimpleLogger logger;
    private final MockRepository mockHolder;
    private final SettingsSaver settingSaver;
    private MockTable mockTable;

    public MockTabPanel(MockRepository mockHolder, MockRuleEditor responseEditor, SettingsSaver settingSaver) {
        this.logger = BurpExtender.getLogger();
        this.mockHolder = mockHolder;
        this.settingSaver = settingSaver;
        prepareGui(responseEditor);
    }

    private void prepareGui(MockRuleEditor responseEditor) {
        setLayout(new BorderLayout(0, 0));
        prepareGitHubFooter();
        prepareCheckBoxTopPanel();
        prepareMain(responseEditor);
    }

    private void prepareMain(MockRuleEditor responseEditor) {
        mockTable = new MockTable("Mock rules", "rules", mockHolder, null, logger, responseEditor);
        JSplitPane mainPanel = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, mockTable, responseEditor.getComponent());
        add(mainPanel, BorderLayout.CENTER);
        mainPanel.setResizeWeight(0.3f);
    }

    private void prepareGitHubFooter() {
        JPanel githubPanel = new JPanel();
        githubPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        add(githubPanel, BorderLayout.SOUTH);
        githubPanel.setLayout(new FlowLayout(FlowLayout.LEFT));

        JLabel newGithubLabel = createLabelURL("https://github.com/ise-spolansky/BurpHttpMock");
        JLabel oldGithubLabel = createLabelURL("https://github.com/LogicalTrust/BurpHttpMock");
        githubPanel.add(oldGithubLabel);
        githubPanel.add(new JLabel("with help from"));
        githubPanel.add(newGithubLabel);
    }

    private void prepareCheckBoxTopPanel() {
        JPanel checkboxPanel = new JPanel();
        add(checkboxPanel, BorderLayout.NORTH);
        checkboxPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));

        JCheckBox chckbxDebug = new JCheckBox("Debug output");
        chckbxDebug.setSelected(settingSaver.isDebugOn());
        chckbxDebug.addActionListener(e -> settingSaver.saveDebugOutput(chckbxDebug.isSelected()));
        checkboxPanel.add(chckbxDebug);

        JButton advanced = new JButton("Advanced");
        advanced.addActionListener(e -> handleAdvancedButton());
        checkboxPanel.add(advanced);
    }

    private void handleAdvancedButton() {
        JTextField largeFileThreshold = new JTextField();
        largeFileThreshold.setText(settingSaver.loadThreshold() + "");
        JCheckBox displayLargeResponsesInEditor = new JCheckBox();
        displayLargeResponsesInEditor.setSelected(settingSaver.loadDisplayLargeResponsesInEditor());
        displayLargeResponsesInEditor.setText("Display too large responses in editor");
        JCheckBox informAboutLargeFiles = new JCheckBox();
        informAboutLargeFiles.setText("Inform about too large responses");
        informAboutLargeFiles.setSelected(settingSaver.loadInformLargeResponsesInEditor());

        Object[] msg = new Object[]{
                "Too large response threshold", largeFileThreshold,
                displayLargeResponsesInEditor,
                informAboutLargeFiles
        };

        int confirm = JOptionPane.showConfirmDialog(this, msg, "Advanced settings", JOptionPane.OK_CANCEL_OPTION);
        if (confirm != JOptionPane.OK_OPTION) {
            return;
        }

        if (largeFileThreshold.getText() != null) {
            try {
                int threshold = Integer.parseInt(largeFileThreshold.getText());
                if (threshold >= 0) {
                    settingSaver.saveThreshold(threshold);
                }
            } catch (NumberFormatException e) {
                logger.debug("Cannot parse " + largeFileThreshold.getText());
            }
        }

        settingSaver.saveDisplayLargeResponsesInEditor(displayLargeResponsesInEditor.isSelected());
        settingSaver.saveInformAboutLargeResponse(informAboutLargeFiles.isSelected());
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
        return "HTTP Mock";
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
