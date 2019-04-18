package net.logicaltrust;

import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import burp.IRequestInfo;
import net.logicaltrust.model.MockEntry;
import net.logicaltrust.persistent.MockRepository;

public class HttpListener implements IProxyListener {

	private IExtensionHelpers helpers;
	private SimpleLogger logger;
	private MockRepository mockRepository;
	private final int port;

	public HttpListener(IExtensionHelpers helpers, SimpleLogger logger, MockRepository mockRepository, int port) {
		this.helpers = helpers;
		this.logger = logger;
		this.mockRepository = mockRepository;
		this.port = port;
	}

	@Override
	public void processProxyMessage(boolean isReq, IInterceptedProxyMessage message) {
		if (mockRepository.hasAnyMock()) {
			IHttpRequestResponse messageInfo = message.getMessageInfo();
			IRequestInfo analyzedReq = helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
			URL url = analyzedReq.getUrl();
			if (isReq) {
				handleRequest(messageInfo, url, message);
			} else if (isMockedResponse(url)) {
				handleResponse(messageInfo, url);
			}
		}
	}

	private boolean isMockedResponse(URL url) {
		return url.getHost().equals("127.0.0.1") && url.getPort() == port;
	}

	private void handleResponse(IHttpRequestResponse messageInfo, URL url) {
		String id = url.getQuery();
		MockEntry entry = mockRepository.getEntryById(id);
		if (entry != null) {
			byte[] body = Arrays.copyOfRange(messageInfo.getRequest(),
					helpers.analyzeRequest(messageInfo.getRequest()).getBodyOffset(), messageInfo.getRequest().length);
			messageInfo.setResponse(entry.getResponseData());
		} else {
			logger.debugForce("Missing response for id " + id);
		}
	}

	private void handleRequest(IHttpRequestResponse messageInfo, URL url, IInterceptedProxyMessage message) {
		Optional<MockEntry> match = mockRepository.findMatch(url);
		if (match.isPresent()) {
			MockEntry matchEntry = match.get();
			logger.debug("Successful URL match: " + url + " with " + matchEntry);
			IHttpService service = helpers.buildHttpService("127.0.0.1", port, false);
			byte[] localReq = helpers.buildHttpMessage(
					Collections.singletonList("POST /?" + matchEntry.getId() + " HTTP/1.0"), messageInfo.getRequest());
			messageInfo.setRequest(localReq);
			messageInfo.setHttpService(service);
			message.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT);
		}
	}

	
}
