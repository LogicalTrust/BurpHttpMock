package net.logicaltrust.model;

import burp.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum MockEntryTypeEnum {
    DirectEntry { //traditional one, just returns whatever was entered by the user in the text box

        @Override
        public byte[] generateResponse(byte[] ruleInput, byte[] incomingRequest, IHttpService incomingHttpService) {
            return ruleInput;
        }

        @Override
        public String toString() {
            return "Basic";
        }
    },
    FileInclusion {
        //matches quoted strings (single or double)
        //group 2 is the contents of the quoted string
        private Pattern quoteParser = Pattern.compile("^([\"'])(.+)\\1$");
        @Override
        public byte[] generateResponse(byte[] entryInput, byte[] incomingRequest, IHttpService incomingHttpService) {
            IExtensionHelpers helpers = BurpExtender.getCallbacks().getHelpers();
            String path = helpers.bytesToString(entryInput);
            Matcher matcher = quoteParser.matcher(path);
            if (matcher.matches()) path = matcher.group(2);
            try {
                return Files.readAllBytes(Paths.get(path));
            } catch (IOException e) {
                return helpers.stringToBytes("500 Internal Server Error\n\nUnable to read file: " +
                        helpers.bytesToString(entryInput));
            }
        }

        @Override
        public String toString() {
            return "File Contents";
        }
    },
    CgiScript {
        @Override
        public byte[] generateResponse(byte[] entryInput, byte[] incomingRequest, IHttpService incomingHttpService) {
            IExtensionHelpers helpers = BurpExtender.getCallbacks().getHelpers();
            Map<String, String> environment = new HashMap<>();
            IRequestInfo requestInfo = helpers.analyzeRequest(incomingHttpService, incomingRequest);
            Map<String, String> headers = requestInfo.getHeaders().stream()
                    .skip(1) //skip the top line
                    .map(String::trim)
                    .map(s -> s.contains(": ") ? s : s + ": ")
                    .collect(Collectors.toMap(s -> s.split(": ")[0].toUpperCase().replaceAll("-", "_"),
                            s -> s.split(": ", 2)[1]));
            URL url = requestInfo.getUrl();
            environment.put("SERVER_SOFTWARE", "Burpsuite HTTP Mock Extension");
            environment.put("SERVER_NAME", url.getHost());
            environment.put("GATEWAY_INTERFACE", "CGI/1.1");
            String[] startLine = requestInfo.getHeaders().get(0).trim().split(" ");
            environment.put("SERVER_PROTOCOL", startLine[startLine.length - 1]);
            //if it can't figure it out, whatever just assume 80
            int port = url.getPort() > 0 ? url.getPort() : url.getDefaultPort() > 0 ? url.getDefaultPort() : 80;
            environment.put("SERVER_PORT", "" + port);
            environment.put("REQUEST_METHOD", requestInfo.getMethod());
            //just for standards compliance, doesn't really matter
            environment.put("REMOTE_ADDR", "127.0.0.1");
            environment.put("REMOTE_PORT", "80");
            if (url.getQuery() != null) environment.put("QUERY_STRING", url.getQuery());
            environment.put("REQUEST_URI", url.getFile());
            if (headers.containsKey("AUTHORIZATION")) environment.put("AUTH_TYPE", headers.get("AUTHORIZATION"));
            if (headers.containsKey("CONTENT_TYPE")) environment.put("CONTENT_TYPE", headers.get("CONTENT_TYPE"));
            if (headers.containsKey("CONTENT_LENGTH")) environment.put("CONTENT_LENGTH", headers.get("CONTENT_LENGTH"));
            headers.forEach((key, value) -> environment.put("HTTP_" + key, value));
            byte[] body = null;
            if (requestInfo.getBodyOffset() > 0 && requestInfo.getBodyOffset() < incomingRequest.length) {
                body = Arrays.copyOfRange(incomingRequest, requestInfo.getBodyOffset(), incomingRequest.length);
            }
            return MockEntryTypeEnum.runProcess(entryInput, body, environment);
        }

        @Override
        public String toString() {
            return "CGI Script";
        }
    },
    UrlRedirect { //redirect to an arbitrary URL

        @Override
        public byte[] generateResponse(byte[] entryInput, byte[] incomingRequest, IHttpService incomingHttpService) {
            //This should never get here - The request should go out to the real URL and not to the local listener
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean handleRequest(byte[] entryInput, IHttpRequestResponse request) {
            IExtensionHelpers helpers = BurpExtender.getCallbacks().getHelpers();
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
                BurpExtender.getLogger().error(e);
                return false;
            }
            request.setHttpService(helpers.buildHttpService(url.getHost(), port, url.getProtocol()));
            IRequestInfo requestInfo = helpers.analyzeRequest(request);
            byte[] body = null;
            if (requestInfo.getBodyOffset() < request.getRequest().length && requestInfo.getBodyOffset() >= 0) {
                body = Arrays.copyOfRange(request.getRequest(),
                        requestInfo.getBodyOffset(), request.getRequest().length);
            }
            String file = url.getFile();
            if (file.equals("")) file = "/"; //handle the edge case for when the user enters domain name with no /
            Stream<String> newTopLine = Stream.of(requestInfo.getMethod() + " " + file + " HTTP/1.1");
            Stream<String> newHeaders = requestInfo.getHeaders().stream()
                    .map(s -> s.toLowerCase().startsWith("host: ") ? "Host: " + url.getHost() : s).skip(1);
            request.setRequest(helpers.buildHttpMessage(Stream.concat(newTopLine, newHeaders)
                    .collect(Collectors.toList()), body));
            return true;
        }

        @Override
        public String toString() {
            return "Redirect to URL";
        }
    },
    Pipe { //pipe full request to a process and return the stdout of that process

        @Override
        public byte[] generateResponse(byte[] entryInput, byte[] incomingRequest, IHttpService incomingHttpService) {
            return MockEntryTypeEnum.runProcess(entryInput, incomingRequest, null);
        }

        @Override
        public String toString() {
            return "Pipe to Process";
        }
    };

    //splits strings by spaces, except when quoted
    //pattern from https://stackoverflow.com/questions/3366281/tokenizing-a-string-but-ignoring-delimiters-within-quotes
    //"([^"]*)"|(\S+)
    private static final Pattern stringSplitter = Pattern.compile("\"([^\"]*)\"|(\\S+)");

    private static byte[] runProcess(byte[] commandLine, byte[] input, Map<String, String> environment) {
        IExtensionHelpers helpers = BurpExtender.getCallbacks().getHelpers();
        try {
            ProcessBuilder pb = new ProcessBuilder();
            List<String> commandWithArgs = new ArrayList<>();
            Matcher m = stringSplitter.matcher(helpers.bytesToString(commandLine));
            while (m.find()) commandWithArgs.add(m.group(1) != null ? m.group(1) : m.group(2));
            pb.command(commandWithArgs);
            Path parent = Paths.get(commandWithArgs.get(0)).getParent();
            if (parent != null) pb.directory(parent.toFile());
            pb.redirectInput(ProcessBuilder.Redirect.PIPE);
            pb.redirectOutput(ProcessBuilder.Redirect.PIPE);
            if (environment != null) pb.environment().putAll(environment);

            Process p = pb.start();
            if (input != null) p.getOutputStream().write(input);
            p.getOutputStream().close();

            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            int length;
            byte[] buffer = new byte[1024];
            while ((length = p.getInputStream().read(buffer)) != -1) stdout.write(buffer, 0, length);

            return stdout.toByteArray();
        } catch (IOException e) {
            BurpExtender.getLogger().error(e);
            return new byte[0];
        }
    }

    public abstract byte[] generateResponse(byte[] ruleInput, byte[] incomingRequest, IHttpService incomingHttpService);

    public boolean handleRequest(byte[] ruleInput, IHttpRequestResponse request) {
        return false;
    }
}
