package burp;

import java.awt.*;

/*
this class provides a non-editable request tab for displaying the request after it has been signed.
 */
public class AWSMessageEditorTab implements IMessageEditorTab
{
    private final String TAB_NAME = "SigV4";
    private IMessageEditorController controller;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private BurpExtender burp;
    private LogWriter logger;
    private ITextEditor messageTextEditor;
    private byte[] content;

    public AWSMessageEditorTab(IMessageEditorController controller, boolean editable, BurpExtender burp, IBurpExtenderCallbacks callbacks, LogWriter logger)
    {
        this.controller = controller;
        this.burp = burp;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.logger = logger;
    }

    @Override
    public String getTabCaption() {
        return TAB_NAME;
    }

    @Override
    public Component getUiComponent() {
        this.messageTextEditor = this.callbacks.createTextEditor();
        this.messageTextEditor.setEditable(false); // this is just a preview of the signed message
        return this.messageTextEditor.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        // enable for requests only
        if (isRequest) {
            IRequestInfo requestInfo = this.helpers.analyzeRequest(content);
            return BurpExtender.isAwsRequest(requestInfo);
        }
        return false;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        this.content = content;

        try {
            AWSSignedRequest signedRequest = new AWSSignedRequest(this.controller.getHttpService(), this.content, this.helpers, this.logger);
            final AWSProfile profile = this.burp.customizeSignedRequest(signedRequest);
            if (profile == null) {
                this.messageTextEditor.setText(this.helpers.stringToBytes(
                        "No profile found for keyId: "+signedRequest.getAccessKeyId()+". Either add it or set a default profile."));
                return;
            }
            this.messageTextEditor.setText(signedRequest.getSignedRequestBytes(profile.secretKey));
            return;
        } catch (Exception exc) {
        }
        this.messageTextEditor.setText(this.helpers.stringToBytes("Failed to sign message with SigV4"));
    }

    @Override
    public byte[] getMessage() {
        return this.content;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        return null;
    }
}
