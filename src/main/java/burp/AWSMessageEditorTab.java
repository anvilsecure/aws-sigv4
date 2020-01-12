package burp;

import java.awt.*;

/*
this class provides a non-editable request tab for displaying the request after it has been signed.
 */
public class AWSMessageEditorTab implements IMessageEditorTab
{
    private final String TAB_NAME = "SigV4";
    private IMessageEditorController controller;
    private BurpExtender burp;
    private LogWriter logger;
    private ITextEditor messageTextEditor;
    private byte[] content;

    public AWSMessageEditorTab(IMessageEditorController controller, boolean editable, BurpExtender burp)
    {
        this.controller = controller;
        this.burp = burp;
        this.logger = burp.logger;
    }

    @Override
    public String getTabCaption() {
        return TAB_NAME;
    }

    @Override
    public Component getUiComponent() {
        this.messageTextEditor = this.burp.callbacks.createTextEditor();
        this.messageTextEditor.setEditable(false); // this is just a preview of the signed message
        return this.messageTextEditor.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        // enable for requests only
        if (isRequest) {
            // we only check if its an aws request here, skipping checks for whether signing is enabled or if its in scope.
            // this is because isEnabled() is only called once, so toggling in-scope only or signing enabled will have no
            // effect on current editor tabs.
            IRequestInfo requestInfo = this.burp.helpers.analyzeRequest(content);
            return BurpExtender.isAwsRequest(requestInfo);
        }
        return false;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        if (this.burp.isSigningEnabled()) {

            // if request is not in scope, display a warning instead
            if (this.burp.isInScopeOnlyEnabled()) {
                IRequestInfo requestInfo = this.burp.helpers.analyzeRequest(this.controller.getHttpService(), content);
                if (!this.burp.callbacks.isInScope(requestInfo.getUrl())) {
                    this.messageTextEditor.setText(this.burp.helpers.stringToBytes("Request URL is not in scope: "+requestInfo.getUrl()));
                    return;
                }
            }

            this.content = content;

            try {
                AWSSignedRequest signedRequest = new AWSSignedRequest(this.controller.getHttpService(), this.content, this.burp);
                final AWSProfile profile = this.burp.customizeSignedRequest(signedRequest);
                if (profile == null) {
                    this.messageTextEditor.setText(this.burp.helpers.stringToBytes(
                            "No profile found for keyId: " + signedRequest.getAccessKeyId() + ". Either add it or set a default profile."));
                    return;
                }
                this.messageTextEditor.setText(signedRequest.getSignedRequestBytes(profile.getCredential()));
                return;
            } catch (Exception exc) {
            }
            this.messageTextEditor.setText(this.burp.helpers.stringToBytes("Failed to sign message with SigV4"));
        }
        else {
            this.messageTextEditor.setText(this.burp.helpers.stringToBytes("SigV4 signing is disabled"));
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
