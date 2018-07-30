package burp;

import java.io.PrintWriter;

import net.logicaltrust.HttpListener;
import net.logicaltrust.context.MockContextMenuFactory;
import net.logicaltrust.SimpleLogger;
import net.logicaltrust.editor.ResponseTextEditor;
import net.logicaltrust.persistent.MockRepository;
import net.logicaltrust.persistent.SettingsSaver;
import net.logicaltrust.server.MockLocalServer;
import net.logicaltrust.tab.MockTabPanel;

public class BurpExtender implements IBurpExtender {

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
		SimpleLogger logger = new SimpleLogger(new PrintWriter(callbacks.getStdout(), true), stderr);
		SettingsSaver settingSaver = new SettingsSaver(callbacks, logger);
		MockRepository mockRepository = new MockRepository(logger, settingSaver);

		ResponseTextEditor responseTextEditor = new ResponseTextEditor(logger, 
				callbacks.createTextEditor(), 
				mockRepository, 
				callbacks.getHelpers(), 
				settingSaver);

		MockTabPanel tab = new MockTabPanel(logger, callbacks, mockRepository, responseTextEditor, settingSaver);
		callbacks.addSuiteTab(tab);

		callbacks.registerProxyListener(new HttpListener(callbacks.getHelpers(), logger, mockRepository, settingSaver.loadPort()));
		
		callbacks.registerContextMenuFactory(new MockContextMenuFactory(logger, callbacks, tab));

		MockLocalServer myMockServer = new MockLocalServer(logger, settingSaver.loadPort());
		callbacks.registerExtensionStateListener(myMockServer);
		new Thread(() -> {
			myMockServer.run();
		}).start();		
	}
	
}
