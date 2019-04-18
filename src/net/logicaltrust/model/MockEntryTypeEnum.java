package net.logicaltrust.model;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.*;
import java.util.Arrays;
import java.util.stream.Collectors;

public enum MockEntryTypeEnum {
    DirectEntry { //traditional one, just returns whatever was entered by the user in the text box
        @Override
        public byte[] generateResponse(byte[] ruleInput, byte[] incomingRequest, IExtensionHelpers helpers) {
            return ruleInput;
        }
    },
    FileInclusion {
        @Override
        public byte[] generateResponse(byte[] entryInput, byte[] incomingRequest, IExtensionHelpers helpers) {
            try {
                return Files.readAllBytes(Paths.get(new String(entryInput)));
            } catch (IOException e) {
                return helpers.stringToBytes("500 Internal Server Error\n\nUnable to read file: " +
                        helpers.bytesToString(entryInput));
            }
        }
    },
    CgiScript {
        @Override
        public byte[] generateResponse(byte[] entryInput, byte[] incomingRequest, IExtensionHelpers helpers) {
            throw new UnsupportedOperationException();
        }
    },
    UrlRedirect { //redirect to an arbitrary URL
        @Override
        public byte[] generateResponse(byte[] entryInput, byte[] incomingRequest, IExtensionHelpers helpers) {
            //This should never get here - The request should go out to the real URL and not to the local listener
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean handleRequest(byte[] entryInput, IHttpRequestResponse request, IExtensionHelpers helpers) {
            URL url;
            int port;
            try {
                url = new URL(helpers.bytesToString(entryInput));
                port = url.getPort();
                if (port < 1) port = url.getDefaultPort();
                if (port < 1 ||
                        (!url.getProtocol().equalsIgnoreCase("http") &&
                                !url.getProtocol().equalsIgnoreCase("https"))) {
                    throw new MalformedURLException();
                }
            }
            catch (MalformedURLException e)
            {
                //TODO: move the logger around so I can access it here
                request.setComment("Malformed URL! Results may not be what you want...");
                return false;
            }
            request.setHttpService(helpers.buildHttpService(url.getHost(), port, url.getProtocol()));
            IRequestInfo requestInfo = helpers.analyzeRequest(request);
            if (requestInfo.getHeaders().stream().anyMatch(s -> s.toLowerCase().startsWith("host: ")))
            {
                byte[] body = null;
                if (requestInfo.getBodyOffset() >= request.getRequest().length || requestInfo.getBodyOffset() < 0)
                {
                    body = Arrays.copyOfRange(request.getRequest(),
                            requestInfo.getBodyOffset(), request.getRequest().length);
                }
                request.setRequest(helpers.buildHttpMessage(requestInfo.getHeaders().stream()
                        .map(s -> s.toLowerCase().startsWith("host: ") ? "Host: " + url.getHost() : s)
                        .collect(Collectors.toList()), body));
            }
            return true;
        }
    },
    Pipe {
        @Override
        public byte[] generateResponse(byte[] entryInput, byte[] incomingRequest, IExtensionHelpers helpers) {
            throw new UnsupportedOperationException();
        }
    };

    public abstract byte[] generateResponse(byte[] ruleInput, byte[] incomingRequest, IExtensionHelpers helpers);
    public boolean handleRequest(byte[] ruleInput, IHttpRequestResponse request, IExtensionHelpers helpers)
    {
        return false;
    }
}
