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

    public AWSMessageEditorTab(IMessageEditorController controller, boolean editable, BurpExtender burp)
    {
        this.controller = controller;
        this.burp = burp;
        this.callbacks = burp.callbacks;
        this.helpers = burp.helpers;
        this.logger = burp.logger;
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
        if (this.burp.signingEnabledCheckBox.isSelected()) {
            this.content = content;

            try {
                AWSSignedRequest signedRequest = new AWSSignedRequest(this.controller.getHttpService(), this.content, this.burp);
                final AWSProfile profile = this.burp.customizeSignedRequest(signedRequest);
                if (profile == null) {
                    this.messageTextEditor.setText(this.helpers.stringToBytes(
                            "No profile found for keyId: " + signedRequest.getAccessKeyId() + ". Either add it or set a default profile."));
                    return;
                }
                this.messageTextEditor.setText(signedRequest.getSignedRequestBytes(profile.getCredentials()));
                return;
            } catch (Exception exc) {
            }
            this.messageTextEditor.setText(this.helpers.stringToBytes("Failed to sign message with SigV4"));
        }
        else {
            this.messageTextEditor.setText(this.helpers.stringToBytes("SigV4 signing is disabled"));
        }
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
