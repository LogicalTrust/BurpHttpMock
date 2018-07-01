package burp;

import java.io.PrintWriter;
import java.util.List;

import net.logicaltrust.HttpListener;
import net.logicaltrust.MockContextMenuFactory;
import net.logicaltrust.SimpleLogger;
import net.logicaltrust.editor.ResponseTextEditor;
import net.logicaltrust.mock.MockEntry;
import net.logicaltrust.mock.MockHolder;
import net.logicaltrust.mock.MockSettingsSaver;
import net.logicaltrust.server.MockLocalServer;
import net.logicaltrust.tab.MockTabPanel;

public class BurpExtender implements IBurpExtender {

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		
		PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
		SimpleLogger logger = new SimpleLogger(new PrintWriter(callbacks.getStdout(), true), stderr);

		MockSettingsSaver settingSaver = new MockSettingsSaver(callbacks, logger);
		List<MockEntry> entries = settingSaver.loadEntries();
		
		MockHolder mockHolder = new MockHolder(logger, entries, settingSaver);
		ResponseTextEditor responseTextEditor = new ResponseTextEditor(logger, callbacks.createTextEditor(), mockHolder, callbacks.getHelpers(), settingSaver);

		MockTabPanel tab = new MockTabPanel(logger, callbacks, mockHolder, responseTextEditor, settingSaver);
		callbacks.addSuiteTab(tab);

		HttpListener httpListener = new HttpListener(callbacks.getHelpers(), logger, mockHolder, settingSaver.loadPort());
		callbacks.registerHttpListener(httpListener);
		
		callbacks.registerContextMenuFactory(new MockContextMenuFactory(logger, callbacks.getHelpers(), tab));
		
		MockLocalServer myMockServer = new MockLocalServer(logger, settingSaver.loadPort());
		callbacks.registerExtensionStateListener(myMockServer);
		new Thread(() -> {
			myMockServer.run();
		}).start();		
	}
	
}
