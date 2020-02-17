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
public class SigProfileEditorReadOnlyDialog extends SigProfileEditorDialog
{
    private SigProfile editedProfile;

    public SigProfile getProfile() { return editedProfile; }

    public SigProfileEditorReadOnlyDialog(Frame owner, String title, boolean modal, SigProfile profile)
    {
        super(owner, title, modal, profile);
        this.okButton.removeActionListener(this.okButton.getActionListeners()[0]);
        this.okButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                //TODO reprompt if no region or service given? will result in blank fields for add signature
                if (profile != null) {
                    editedProfile = new SigProfile.Builder(profile)
                            .withRegion(regionTextField.getText())
                            .withService(serviceTextField.getText())
                            .build();
                }
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

    public void disableForEdit()
    {
        disableField(this.nameTextField);
        disableField(this.profileKeyIdTextField);
        disableField(this.secretKeyTextField);
        disableField(this.sessionTokenTextField);

        providerPanel.setVisible(false);
        pack();
    }
}
