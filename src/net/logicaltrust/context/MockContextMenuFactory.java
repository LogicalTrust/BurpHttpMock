package net.logicaltrust.context;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import burp.*;
import net.logicaltrust.SimpleLogger;
import net.logicaltrust.model.MockEntry;
import net.logicaltrust.model.MockRule;
import net.logicaltrust.persistent.MockAdder;

public class MockContextMenuFactory implements IContextMenuFactory {


	private final IBurpExtenderCallbacks callbacks;
	private SimpleLogger logger;
	private IContextMenuInvocation invocation;
	private IExtensionHelpers helpers;
	private MockAdder mockAdder;
	
	public MockContextMenuFactory(SimpleLogger logger, IBurpExtenderCallbacks callbacks, MockAdder mockAdder) {
		this.logger = logger;
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
		this.mockAdder = mockAdder;
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		this.invocation = invocation;
		JMenuItem jMenuItem = new JMenuItem("Mock HTTP response");
		jMenuItem.addActionListener(e -> actionPerformed(AddMockOption.FROM_URL));
		JMenuItem jMenuItemWithoutQuery = new JMenuItem("Mock HTTP response (URL without query)");
		jMenuItemWithoutQuery.addActionListener(e -> actionPerformed(AddMockOption.FROM_URL_WITHOUT_QUERY));
		List<JMenuItem> list = new ArrayList<>();
		list.add(jMenuItem);
		list.add(jMenuItemWithoutQuery);
		if (this.invocation.getInvocationContext() == invocation.CONTEXT_TARGET_SITE_MAP_TREE) {
			JMenuItem jMenuBranch = new JMenuItem("Moch this branch");
			jMenuBranch.addActionListener(e -> actionPerformed(AddMockOption.SITEMAP));
			list.add(jMenuBranch);
		}
		return list;
	}

	public void actionPerformed(AddMockOption addOption) {
		try {
			IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
			
			if (selectedMessages == null) {
				logger.debug("No selected messages");
				return;
			}
			
			for (IHttpRequestResponse msg : selectedMessages) {
				URL analyzedURL = getAnalyzedURL(msg);
				if (addOption == AddMockOption.SITEMAP) {
					processSitemap(analyzedURL);
				} else {
					addMock(addOption.isFullUrl(), msg, analyzedURL);
				}
			}
		} catch (Exception ex) {
			logger.getStderr().println("Cannot mock messages");
			ex.printStackTrace(logger.getStderr());
		}
	}

	private void processSitemap(URL rootURL) {

		String url = rootURL.getProtocol() + "://" + rootURL.getHost() + (rootURL.getPort() != rootURL.getDefaultPort() ? (":" + rootURL.getPort()) : "") + rootURL.getPath();

		IHttpRequestResponse[] siteMap = callbacks.getSiteMap(url);
		for (IHttpRequestResponse msg : siteMap) {
			if (msg.getRequest() == null || msg.getResponse() == null) {
				continue;
			}
			URL analyzedURL = getAnalyzedURL(msg);
			addMock(AddMockOption.SITEMAP.isFullUrl(), msg, analyzedURL);
		}
	}

	private URL getAnalyzedURL(IHttpRequestResponse msg) {
		IRequestInfo analyzedReq = helpers.analyzeRequest(msg.getHttpService(), msg.getRequest());
		URL analyzedURL = analyzedReq.getUrl();
		return analyzedURL;
	}

	private void addMock(boolean fullURL, IHttpRequestResponse msg, URL analyzedURL) {
		MockRule mockRule = null;
		if (fullURL) {
			mockRule = MockRule.fromURL(analyzedURL);
		} else {
			 mockRule = MockRule.fromURLwithoutQuery(analyzedURL);
		}
		MockEntry mockEntry = new MockEntry(true, mockRule, msg.getResponse());
		mockAdder.addMock(mockEntry);
		logger.debug("Mock added for " + mockRule);
	}

}
