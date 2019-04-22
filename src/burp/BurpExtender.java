package burp;

import java.io.PrintWriter;

import net.logicaltrust.HttpListener;
import net.logicaltrust.context.MockContextMenuFactory;
import net.logicaltrust.SimpleLogger;
import net.logicaltrust.editor.MockRuleEditor;
import net.logicaltrust.persistent.MockRepository;
import net.logicaltrust.persistent.SettingsSaver;
import net.logicaltrust.server.MockLocalServer;
import net.logicaltrust.tab.MockTabPanel;

public class BurpExtender implements IBurpExtender {
	private static IBurpExtenderCallbacks callbacks = null;

	private static SimpleLogger logger = null;
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		BurpExtender.callbacks = callbacks;
		PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
		BurpExtender.logger = new SimpleLogger(new PrintWriter(callbacks.getStdout(), true), stderr);
		SettingsSaver settingSaver = new SettingsSaver();
		MockRepository mockRepository = new MockRepository(settingSaver);

		MockRuleEditor mockRuleEditor = new MockRuleEditor(
				callbacks.createTextEditor(),
				mockRepository,
				settingSaver);

		MockTabPanel tab = new MockTabPanel(mockRepository, mockRuleEditor, settingSaver);
		callbacks.addSuiteTab(tab);

		callbacks.registerProxyListener(new HttpListener(mockRepository, settingSaver.loadPort()));
		
		callbacks.registerContextMenuFactory(new MockContextMenuFactory(tab, settingSaver));

		MockLocalServer myMockServer = new MockLocalServer(settingSaver.loadPort());
		callbacks.registerExtensionStateListener(myMockServer);
		new Thread(myMockServer::run).start();
	}

	public static IBurpExtenderCallbacks getCallbacks()
	{
		return callbacks;
	}

	public static SimpleLogger getLogger() {
		return logger;
	}
}
