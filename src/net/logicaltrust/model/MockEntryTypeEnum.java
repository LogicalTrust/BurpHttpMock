package net.logicaltrust.model;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
            } catch (MalformedURLException e) {
                //TODO: move the logger around so I can access it here
                request.setComment("Malformed URL! Results may not be what you want...");
                return false;
            }
            request.setHttpService(helpers.buildHttpService(url.getHost(), port, url.getProtocol()));
            IRequestInfo requestInfo = helpers.analyzeRequest(request);
            byte[] body = null;
            if (requestInfo.getBodyOffset() >= request.getRequest().length || requestInfo.getBodyOffset() < 0) {
                body = Arrays.copyOfRange(request.getRequest(),
                        requestInfo.getBodyOffset(), request.getRequest().length);
            }
            Stream<String> newTopLine = Stream.of(requestInfo.getMethod() + " " + url.getFile() + " HTTP/1.1");
            Stream<String> newHeaders = requestInfo.getHeaders().stream()
                    .map(s -> s.toLowerCase().startsWith("host: ") ? "Host: " + url.getHost() : s).skip(1);
            request.setRequest(helpers.buildHttpMessage(Stream.concat(newTopLine, newHeaders)
                    .collect(Collectors.toList()), body));
            return true;
        }
    },
    Pipe { //pipe full request to a process and return the stdout of that process
        //splits strings by spaces, except when quoted
        //pattern and code adapted from https://stackoverflow.com/a/7804472
        Pattern stringSplitter = Pattern.compile("([^\"]\\S*|\".+?\")\\s*");
        @Override
        public byte[] generateResponse(byte[] entryInput, byte[] incomingRequest, IExtensionHelpers helpers) {
            try {
                ProcessBuilder pb = new ProcessBuilder();
                List<String> commandWithArgs = new ArrayList<>();
                Matcher m = stringSplitter.matcher(helpers.bytesToString(entryInput));
                while (m.find()) commandWithArgs.add(m.group(1));
                pb.command(commandWithArgs);
                Path parent = Paths.get(commandWithArgs.get(0)).getParent();
                if (parent != null) pb.directory(parent.toFile());
                pb.redirectInput(ProcessBuilder.Redirect.PIPE);
                pb.redirectOutput(ProcessBuilder.Redirect.PIPE);
                Process p = pb.start();
                p.getOutputStream().write(incomingRequest);
                p.getOutputStream().close();

                ByteArrayOutputStream stdout = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                while (p.getInputStream().read(buffer) != -1) stdout.write(buffer);

                return stdout.toByteArray();
            } catch (IOException e) {
                return helpers.stringToBytes(e.toString());
            }
        }
    };

    public abstract byte[] generateResponse(byte[] ruleInput, byte[] incomingRequest, IExtensionHelpers helpers);
    public boolean handleRequest(byte[] ruleInput, IHttpRequestResponse request, IExtensionHelpers helpers)
    {
        return false;
    }
}
