package burp;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import net.logicaltrust.SimpleLogger;
import net.logicaltrust.mock.MockEntry;
import net.logicaltrust.mock.MockHolder;
import net.logicaltrust.mock.MockRule;

public class MyContextMenuFactory implements IContextMenuFactory, ActionListener {

	private SimpleLogger logger;
	private IContextMenuInvocation invocation;
	private IExtensionHelpers helpers;
	private MockHolder mockHolder;
	
	public MyContextMenuFactory(SimpleLogger logger, IExtensionHelpers helpers, MockHolder mockHolder) {
		this.logger = logger;
		this.helpers = helpers;
		this.mockHolder = mockHolder;
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		this.invocation = invocation;
		JMenuItem jMenuItem = new JMenuItem("Mock response");
		jMenuItem.addActionListener(this);
		List<JMenuItem> list = new ArrayList<>();
		list.add(jMenuItem);
		return list;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		try {
			IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
			
			if (selectedMessages == null) {
				logger.debug("No selected messages");
				return;
			}
			
			for (IHttpRequestResponse msg : selectedMessages) {
				IRequestInfo analyzedReq = helpers.analyzeRequest(msg.getHttpService(), msg.getRequest());
				URL analyzedURL = analyzedReq.getUrl();
				//wrong - add through table
				MockRule mockRule = new MockRule(analyzedURL.getProtocol(), 
						decorateFull(analyzedURL.getHost()), 
						decorateFull(analyzedURL.getPort()+""), 
						decorateFromStart(analyzedURL.getPath()));
				byte[] response = msg.getResponse();
				if (response == null) response = new byte[0];
				MockEntry mockEntry = new MockEntry(mockRule, response);
				mockHolder.add(mockEntry);
				logger.debug("Mock added for " + mockRule);
			}
		} catch (Exception ex) {
			logger.getStderr().println("Cannot mock messages");
			ex.printStackTrace(logger.getStderr());
		}
	}
	
	private String decorateFull(String value) {
		return "^" + quote(value) + "$";
	}
	
	private String decorateFromStart(String value) {
		return "^" + quote(value) + ".*";
	}
	
	private String quote(String value) {
		return value.replaceAll("\\.", "\\\\.");
	}

}
