package net.logicaltrust.context;

public enum AddMockOption {

    FROM_URL(true),

    FROM_URL_WITHOUT_QUERY(false),

    SITEMAP(true);

    private final boolean fullUrl;

    AddMockOption(boolean fullUrl) {
        this.fullUrl = fullUrl;
    }

    public boolean isFullUrl() {
        return fullUrl;
    }
}
