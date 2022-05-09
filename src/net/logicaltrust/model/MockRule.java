package net.logicaltrust.model;

import com.google.gson.annotations.Expose;

import java.net.URL;
import java.util.regex.Pattern;

public class MockRule {

    public static final String DEFAULT_METHOD = ".*";
    private static final String[] REGEX_SPECIAL_CHARACTERS = new String[]{"\\.", "\\[", "\\]", "\\{", "\\}", "\\(", "\\)", "\\<", "\\>", "\\*", "\\+", "\\-", "\\=", "\\?", "\\^", "\\|"};
    @Expose
    private String method;
    @Expose
    private MockProtocolEnum protocol;
    @Expose
    private String host;
    @Expose
    private String port;
    @Expose
    private String path;
    private Pattern pathRegex;
    private Pattern portRegex;
    private Pattern hostRegex;
    private Pattern methodRegex;

    public MockRule(MockProtocolEnum protocol, String method, String host, String port, String path) {
        this.setHost(host);
        this.setPath(path);
        this.setPort(port);
        this.setMethod(method);
        this.setProtocol(protocol);
    }

    public MockRule() {

    }

    public static MockRule fromURLwithoutQuery(URL url, String method) {
        return new MockRule(MockProtocolEnum.fromURL(url),
                decorateFull(method),
                decorateFull(url.getHost()),
                decorateFull(getPortFromURL(url)),
                decorateFromStart(url.getPath()));
    }

    public static MockRule fromURL(URL url, String method) {
        return new MockRule(MockProtocolEnum.fromURL(url),
                decorateFull(method),
                decorateFull(url.getHost()),
                decorateFull(getPortFromURL(url)),
                decorateFull(url.getFile()));
    }

    private static String getPortFromURL(URL url) {
        return (url.getPort() != -1 ? url.getPort() : url.getDefaultPort()) + "";
    }

    private static String decorateFull(String value) {
        return "^" + escape(value) + "$";
    }

    private static String decorateFromStart(String value) {
        return "^" + escape(value) + ".*";
    }

    private static String escape(String before) {
        before = before.replaceAll("\\\\", "\\\\\\\\");
        before = before.replaceAll("\\$", "#");
        String after = before.replaceAll("#", "\\\\\\$");
        for (String s : REGEX_SPECIAL_CHARACTERS) {
            after = after.replaceAll(s, "\\" + s);
        }
        return after;
    }

    public boolean matches(URL url, String method) {
        return protocol.matches(url.getProtocol())
                && methodRegex.matcher(method).matches()
                && hostRegex.matcher(url.getHost()).matches()
                && portRegex.matcher(url.getPort() + "").matches()
                && pathRegex.matcher(url.getFile()).matches();
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
        this.hostRegex = Pattern.compile(host);
    }

    public String getPort() {
        return port;
    }

    public void setPort(String port) {
        this.port = port;
        this.portRegex = Pattern.compile(port);
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
        this.pathRegex = Pattern.compile(path);
    }

    public MockProtocolEnum getProtocol() {
        return protocol;
    }

    public void setProtocol(MockProtocolEnum protocol) {
        this.protocol = protocol;
    }
    public String getMethod() {
        return this.method;
    }
    public void setMethod(String method) {
        this.method = method;
        this.methodRegex = Pattern.compile(method);
    }

    public void setMethodDecorated(String method) {
        this.setMethod(decorateFull(method));
    }

    @Override
    public String toString() {
        return "MockRule [protocol=" + protocol + ", host=" + host + ", port=" + port + ", method=" + method + ", path=" + path + "]";
    }

    public MockRule duplicate() {
        return new MockRule(this.protocol, this.method, this.host, this.port, this.path);
    }

}
