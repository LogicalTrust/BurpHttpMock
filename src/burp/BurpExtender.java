package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import net.logicaltrust.MontoyaHttpHandler;
import net.logicaltrust.SimpleLogger;
import net.logicaltrust.context.MockContextMenuFactory;
import net.logicaltrust.editor.MockRuleEditor;
import net.logicaltrust.persistent.MockRepository;
import net.logicaltrust.persistent.SettingsSaver;
import net.logicaltrust.tab.MockTabPanel;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, BurpExtension {
    private static IBurpExtenderCallbacks callbacks = null;

    private static SimpleLogger logger = null;
    private MockRepository mockRepository;
    private MontoyaApi montoyaApi;
    private boolean handlersRegistered;

    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public static SimpleLogger getLogger() {
        return logger;
    }

    @Override
    public synchronized void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
        BurpExtender.logger = new SimpleLogger(new PrintWriter(callbacks.getStdout(), true), stderr);
        SettingsSaver settingSaver = new SettingsSaver();
        mockRepository = new MockRepository(settingSaver);

        MockRuleEditor mockRuleEditor = new MockRuleEditor(
                callbacks.createTextEditor(),
                mockRepository,
                settingSaver);

        MockTabPanel tab = new MockTabPanel(mockRepository, mockRuleEditor, settingSaver);
        callbacks.addSuiteTab(tab);

        callbacks.registerContextMenuFactory(new MockContextMenuFactory(tab, settingSaver));
        registerHandlersIfReady();
    }

    @Override
    public synchronized void initialize(MontoyaApi api) {
        montoyaApi = api;
        registerHandlersIfReady();
    }

    private void registerHandlersIfReady() {
        if (handlersRegistered || montoyaApi == null || mockRepository == null) {
            return;
        }

        MontoyaHttpHandler handler = new MontoyaHttpHandler(mockRepository, callbacks.getHelpers(), logger);
        montoyaApi.proxy().registerRequestHandler(handler);
        montoyaApi.http().registerHttpHandler(handler);
        handlersRegistered = true;
    }
}
