package net.logicaltrust;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import burp.IExtensionHelpers;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import net.logicaltrust.mock.MockHolder;

public class MyHttpListener implements IHttpListener {

	private IExtensionHelpers helpers;
	private SimpleLogger logger;
	private MockHolder mockHolder;

	public MyHttpListener(IExtensionHelpers helpers, SimpleLogger logger, MockHolder mockHolder) {
		this.helpers = helpers;
		this.logger = logger;
		this.mockHolder = mockHolder;
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean isReq, IHttpRequestResponse messageInfo) {
		if (isReq) {
			byte[] request = messageInfo.getRequest();
			IHttpService httpService = messageInfo.getHttpService();
			IRequestInfo analyzedReq = helpers.analyzeRequest(httpService, request);
			URL url = analyzedReq.getUrl();
			logger.debug(url + "");
			String match = mockHolder.findMatch(url);
			if (match != null) {
				IHttpService service = helpers.buildHttpService("localhost", 8765, false);
				List<String> headers = new ArrayList<>();
				headers.add("GET /" + match  + " HTTP/1.0");
				byte[] buildHttpMessage = helpers.buildHttpMessage(headers, null);
				logger.debug("Msg: " + new String(buildHttpMessage));
				messageInfo.setHttpService(service);
			}
		}
	}
	
}
