package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/*
this class provides a dialog for filling out missing profile fields when adding sigv4 to an unsigned request. since region and service are
optional profile parameters, this dialog can be used to prompt the user for them without modifying the profile. the reason service and
region are optional is because an empty value means the region and service from the original request should be used. however, when adding
a new signature, service and region are not available in the original request.
 */
public class AWSProfileEditorReadOnlyDialog extends AWSProfileEditorDialog
{
    private AWSProfile editedProfile;
    private static final Color disabledColor = new Color(165, 161, 161);

    public AWSProfile getProfile() { return editedProfile; }

    public AWSProfileEditorReadOnlyDialog(Frame owner, String title, boolean modal, AWSProfile profile, BurpExtender burp)
    {
        super(owner, title, modal, profile, burp);
        this.okButton.removeActionListener(this.okButton.getActionListeners()[0]);
        this.okButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                editedProfile = new AWSProfile(nameTextField.getText(), keyIdTextField.getText(), secretKeyTextField.getText(),
                        regionTextField.getText(), serviceTextField.getText(), assumeRoleTextField.getText(), burp);
                setVisible(false);
                dispose();
            }
        });
    }

    private void disableField(JTextField textField)
    {
        textField.setEditable(false);
        textField.setForeground(disabledColor);
        textField.setFocusable(false);
    }

    public void disableName()
    {

        disableField(this.nameTextField);
    }

    public void disableKeyId()
    {

        disableField(this.keyIdTextField);
    }

    public void disableSecret()
    {
        disableField(this.secretKeyTextField);
    }

    public void disableAssumeRoleArn()
    {
        disableField(this.assumeRoleTextField);
    }
}
