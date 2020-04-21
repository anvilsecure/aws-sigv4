package burp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/*
This class provides a dialog for filling out missing signature fields when adding
sigv4 to a request. Since region and service are optional profile parameters, this
dialog can be used to prompt the user for them without modifying the profile. The
reason service and region are optional is because an empty value means the region
and service from the original request should be used. However, when adding a new
signature, service and region are not available in the original request (located
in the Authorization header).
*/
public class SigProfileEditorReadOnlyDialog extends SigProfileEditorDialog
{
    private SigProfile editedProfile;

    public SigProfile getProfile() { return editedProfile; }

    public SigProfileEditorReadOnlyDialog(Frame owner, String title, boolean modal, SigProfile profile)
    {
        super(owner, title, modal, profile);
        if (profile == null) {
            throw new IllegalArgumentException("Profile editor dialog requires an existing profile to populate fields");
        }
        this.regionTextField.setHintText("Required");
        this.serviceTextField.setHintText("Required");
        if (this.regionTextField.getText().isEmpty()) {
            // populate region from the environment (if defined)
            this.regionTextField.setText(SigProfile.getDefaultRegion());
        }

        focusEmptyField();

        this.okButton.removeActionListener(this.okButton.getActionListeners()[0]);
        this.okButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                try {
                    // don't allow empty region and service. a user can manually edit these in the message editor if they desire.
                    final String region = (regionTextField.getText().length() > 0) ? regionTextField.getText() : profile.getRegion();
                    final String service = (serviceTextField.getText().length() > 0) ? serviceTextField.getText() : profile.getService();
                    if (region.equals("") || service.equals("")) {
                        throw new IllegalArgumentException("region and service must not be blank");
                    }
                    editedProfile = new SigProfile.Builder(profile)
                            .withRegion(region)
                            .withService(service)
                            .build();
                    setVisible(false);
                    dispose();
                } catch (IllegalArgumentException exc) {
                    setStatusLabel("Invalid settings: " + exc.getMessage());
                }
            }
        });
    }

    public void focusEmptyField() {
        this.serviceTextField.requestFocus();
        if (this.regionTextField.getText().isEmpty()) {
            this.regionTextField.requestFocus();
        }
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
        setLocationRelativeTo(SwingUtilities.getWindowAncestor(BurpExtender.getBurp().getUiComponent()));
    }
}
