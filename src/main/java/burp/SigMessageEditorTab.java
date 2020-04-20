package burp;

import java.awt.*;

/*
this class provides a non-editable request tab for displaying the request after it has been signed.
 */
public class SigMessageEditorTab implements IMessageEditorTab
{
    private IMessageEditorController controller;
    private final BurpExtender burp = BurpExtender.getBurp();
    private ITextEditor messageTextEditor;
    private byte[] content;

    public SigMessageEditorTab(IMessageEditorController controller, boolean editable)
    {
        this.controller = controller;
    }

    @Override
    public String getTabCaption() {
        return BurpExtender.DISPLAY_NAME;
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
            return BurpExtender.isAws4Request(requestInfo);
        }
        return false;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        if (this.burp.isSigningEnabled()) {
            IRequestInfo requestInfo = this.burp.helpers.analyzeRequest(this.controller.getHttpService(), content);

            // if request is not in scope, display a warning instead
            if (this.burp.isInScopeOnlyEnabled()) {
                if (!this.burp.callbacks.isInScope(requestInfo.getUrl())) {
                    this.messageTextEditor.setText(this.burp.helpers.stringToBytes("Request URL is not in scope: "+requestInfo.getUrl()));
                    return;
                }
            }

            this.content = content;
            final SigProfile profile = this.burp.getSigningProfile(requestInfo.getHeaders());
            this.messageTextEditor.setText(this.burp.helpers.stringToBytes("Signing request..."));

            // thread this to prevent blocking the UI thread. signRequest can trigger an http request if temp credentials are configured.
            (new Thread(() -> {
                try {
                    final byte[] requestBytes = burp.signRequest(this.controller.getHttpService(), this.content, profile);
                    if (requestBytes == null) {
                        this.messageTextEditor.setText(this.burp.helpers.stringToBytes("Failed to sign request with profile: " + profile.getName()));
                        return;
                    }
                    this.messageTextEditor.setText(requestBytes);
                    return;
                } catch (Exception ignored) {
                }
                this.messageTextEditor.setText(this.burp.helpers.stringToBytes("Failed to sign message with SigV4"));
            })).start();
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
