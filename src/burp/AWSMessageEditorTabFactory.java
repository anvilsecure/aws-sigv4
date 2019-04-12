package burp;

public class AWSMessageEditorTabFactory implements IMessageEditorTabFactory
{
    private BurpExtender burp;
    private IBurpExtenderCallbacks callbacks;
    private LogWriter logger;

    public AWSMessageEditorTabFactory(BurpExtender burp, IBurpExtenderCallbacks callbacks, LogWriter logger)
    {
        this.burp = burp;
        this.callbacks = callbacks;
        this.logger = logger;
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new AWSMessageEditorTab(controller, editable, this.burp, this.callbacks, this.logger);
    }
}
