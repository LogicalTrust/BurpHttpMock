package net.logicaltrust;

import java.net.URL;
import java.util.Arrays;
import java.util.Optional;

import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import net.logicaltrust.model.MockEntry;
import net.logicaltrust.persistent.MockRepository;

public class HttpListener implements IHttpListener {

	private IExtensionHelpers helpers;
	private SimpleLogger logger;
	private MockRepository mockHolder;
	private final int port;

	public HttpListener(IExtensionHelpers helpers, SimpleLogger logger, MockRepository mockHolder, int port) {
		this.helpers = helpers;
		this.logger = logger;
		this.mockHolder = mockHolder;
		this.port = port;
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean isReq, IHttpRequestResponse messageInfo) {
		if (mockHolder.hasAnyMock()) {
			
			IRequestInfo analyzedReq = helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
			URL url = analyzedReq.getUrl();
			
			if (isReq) {
				Optional<MockEntry> match = mockHolder.findMatch(url);
				if (match.isPresent()) {
					MockEntry matchEntry = match.get();
					logger.debug("Successful URL match: " + url + " with " + matchEntry);
					IHttpService service = helpers.buildHttpService("localhost", port, false);
					byte[] localReq = helpers.buildHttpMessage(Arrays.asList("GET /?" + matchEntry.getId() + " HTTP/1.0"), null);
					messageInfo.setRequest(localReq);
					messageInfo.setHttpService(service);
				}
			} else if (url.getHost().equals("localhost") && url.getPort() == port) {
				String id = url.getQuery();
				MockEntry entry = mockHolder.getEntry(id);
				if (entry != null) {
					messageInfo.setResponse(entry.getResponse());
				} else {
					logger.debugForce("Missing response for id " + id);
				}
			}
		}
	}
	
}
