package burp;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class AWSProfileEditorDialog extends JDialog
{

    protected JTextField nameTextField;
    protected JTextField keyIdTextField;
    protected JTextField secretKeyTextField;
    protected JTextField regionTextField;
    protected JTextField serviceTextField;
    protected JTextField assumeRoleTextField;
    protected JButton okButton;

    private static GridBagConstraints newConstraint(int gridx, int gridy, int gridwidth, int gridheight)
    {
        GridBagConstraints c = new GridBagConstraints();
        c.gridy = gridy;
        c.gridx = gridx;
        c.gridwidth = gridwidth;
        c.gridheight = gridheight;
        return c;
    }

    private static GridBagConstraints newConstraint(int gridx, int gridy, int anchor)
    {
        GridBagConstraints c = newConstraint(gridx, gridy, 1, 1);
        c.anchor = anchor;
        return c;
    }

    private static GridBagConstraints newConstraint(int gridx, int gridy)
    {
        return newConstraint(gridx, gridy, 1, 1);
    }

    /*
    return a dialog with a form for editing profiles. optional profile param can be used to populate the form.
    set profile to null for a create form.
     */
    public AWSProfileEditorDialog(Frame owner, String title, boolean modal, AWSProfile profile, BurpExtender burp)
    {
        super(owner, title, modal);
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        JPanel outerPanel = new JPanel(new GridBagLayout());
        outerPanel.setBorder(new TitledBorder(""));

        outerPanel.add(new JLabel("Name"), newConstraint(0, 0, GridBagConstraints.FIRST_LINE_START));
        this.nameTextField = new JTextField("", 40);
        outerPanel.add(nameTextField, newConstraint(1, 0));
        outerPanel.add(new JLabel("KeyId"), newConstraint(0, 1, GridBagConstraints.FIRST_LINE_START));
        this.keyIdTextField = new JTextField("", 40);
        outerPanel.add(keyIdTextField, newConstraint(1, 1));
        outerPanel.add(new JLabel("SecretKey"), newConstraint(0, 2, GridBagConstraints.FIRST_LINE_START));
        this.secretKeyTextField = new JTextField("", 40);
        outerPanel.add(secretKeyTextField, newConstraint(1, 2));
        outerPanel.add(new JLabel("Region"), newConstraint(0, 3, GridBagConstraints.FIRST_LINE_START));
        this.regionTextField = new JTextField("", 40);
        outerPanel.add(regionTextField, newConstraint(1, 3));
        outerPanel.add(new JLabel("Service"), newConstraint(0, 4, GridBagConstraints.FIRST_LINE_START));
        this.serviceTextField = new JTextField("", 40);
        outerPanel.add(serviceTextField, newConstraint(1, 4));
        outerPanel.add(new JLabel("RoleArn"), newConstraint(0, 5, GridBagConstraints.FIRST_LINE_START));
        this.assumeRoleTextField = new JTextField("", 40);
        outerPanel.add(assumeRoleTextField, newConstraint(1, 5));

        JLabel statusLabel = new JLabel("<html><i>Ok to submit</i></html>");
        statusLabel.setForeground(burp.textOrange);
        this.okButton = new JButton("Ok");
        JButton cancelButton = new JButton("Cancel");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        outerPanel.add(statusLabel, newConstraint(0, 6, 2, 1));
        outerPanel.add(buttonPanel, newConstraint(0, 7, 2, 1));

        cancelButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                setVisible(false);
            }
        });
        okButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                if (burp.updateProfile(profile, new AWSProfile(nameTextField.getText(), keyIdTextField.getText(), secretKeyTextField.getText(),
                        regionTextField.getText(), serviceTextField.getText(), assumeRoleTextField.getText(), burp))) {
                    setVisible(false);
                    dispose();
                }
                else {
                    statusLabel.setText("<html><i>Invalid settings. Ensure keyId is unique and name is not empty.</i></html>");
                }
            }
        });

        // populate fields with existing profile for an "edit" dialog.
        applyProfile(profile);

        add(outerPanel);
        pack();
        setLocationRelativeTo(burp.getUiComponent());
    }

    protected void applyProfile(final AWSProfile profile)
    {
        if (profile != null) {
            nameTextField.setText(profile.name);
            keyIdTextField.setText(profile.accessKeyId);
            secretKeyTextField.setText(profile.secretKey);
            regionTextField.setText(profile.region);
            serviceTextField.setText(profile.service);
            if (profile.getAssumeRole() != null) {
                assumeRoleTextField.setText(profile.getAssumeRole().getRoleArn());
            }
        }
    }
}
