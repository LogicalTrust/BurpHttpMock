package net.logicaltrust;

import burp.IExtensionHelpers;
import burp.IHttpService;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import net.logicaltrust.model.MockEntry;
import net.logicaltrust.model.MockEntryTypeEnum;
import net.logicaltrust.persistent.MockRepository;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.BooleanSupplier;

public class MontoyaHttpHandler implements HttpHandler, ProxyRequestHandler {

    private static final String INTERNAL_ERROR = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
    private static final String INVALID_REDIRECT = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";

    private final BooleanSupplier hasAnyMock;
    private final BiFunction<URL, String, Optional<MockEntry>> findMock;
    private final IExtensionHelpers helpers;
    private final SimpleLogger logger;

    public MontoyaHttpHandler(MockRepository mockRepository, IExtensionHelpers helpers, SimpleLogger logger) {
        this(mockRepository::hasAnyMock, mockRepository::findMatch, helpers, logger);
    }

    MontoyaHttpHandler(BooleanSupplier hasAnyMock,
                       BiFunction<URL, String, Optional<MockEntry>> findMock,
                       IExtensionHelpers helpers, SimpleLogger logger) {
        this.hasAnyMock = hasAnyMock;
        this.findMock = findMock;
        this.helpers = helpers;
        this.logger = logger;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        if (findMatch(request).isPresent()) {
            return ProxyRequestReceivedAction.doNotIntercept(request);
        }
        return ProxyRequestReceivedAction.continueWith(request);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        return ProxyRequestToBeSentAction.continueWith(request);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        if (!request.toolSource().isFromTool(ToolType.PROXY)
                && !request.toolSource().isFromTool(ToolType.REPEATER)) {
            return RequestToBeSentAction.continueWith(request);
        }

        Optional<MockEntry> match = findMatch(request);
        if (!match.isPresent()) {
            return RequestToBeSentAction.continueWith(request);
        }

        MockEntry entry = match.get();
        logger.debug("Successful URL match: " + request.method() + " " + request.url() + " with " + entry);

        if (entry.getEntryType() == MockEntryTypeEnum.UrlRedirect) {
            try {
                return RequestToBeSentAction.continueWith(redirect(request, entry.getEntryInput()));
            } catch (Exception e) {
                logger.error(e);
                return spoof(INVALID_REDIRECT);
            }
        }

        try {
            HttpService service = request.httpService();
            // Existing response generators still use the legacy service type.
            IHttpService legacyService = helpers.buildHttpService(service.host(), service.port(), service.secure());
            byte[] response = entry.handleResponse(request.toByteArray().getBytes(), legacyService);
            return RequestToBeSentAction.spoof(HttpResponse.httpResponse(ByteArray.byteArray(response)));
        } catch (RuntimeException e) {
            logger.error(e);
            return spoof(INTERNAL_ERROR);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        return ResponseReceivedAction.continueWith(response);
    }

    private Optional<MockEntry> findMatch(HttpRequest request) {
        if (!hasAnyMock.getAsBoolean()) {
            return Optional.empty();
        }
        try {
            URL url = new URL(request.url());
            if (url.getPort() < 0) {
                url = new URL(url.getProtocol(), url.getHost(), request.httpService().port(), url.getFile());
            }
            return findMock.apply(url, request.method());
        } catch (MalformedURLException e) {
            logger.error(e);
            return Optional.empty();
        }
    }

    private HttpRequest redirect(HttpRequest request, byte[] target) throws MalformedURLException {
        URL url = new URL(helpers.bytesToString(target));
        String protocol = url.getProtocol();
        if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
            throw new MalformedURLException("Unsupported redirect protocol: " + protocol);
        }
        int port = url.getPort() > 0 ? url.getPort() : url.getDefaultPort();
        if (port < 1 || port > 65535 || url.getHost().isEmpty()) {
            throw new MalformedURLException("Invalid redirect destination");
        }
        String path = url.getFile();
        if (path.isEmpty() || path.startsWith("?")) {
            path = "/" + path;
        }
        String hostHeader = url.getHost();
        if (url.getPort() > 0 && url.getPort() != url.getDefaultPort()) {
            hostHeader += ":" + port;
        }
        return request.withService(HttpService.httpService(url.getHost(), port, "https".equalsIgnoreCase(protocol)))
                .withPath(path)
                .withHeader("Host", hostHeader);
    }

    private RequestToBeSentAction spoof(String response) {
        return RequestToBeSentAction.spoof(HttpResponse.httpResponse(response));
    }
}
