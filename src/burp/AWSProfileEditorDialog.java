package burp;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;

public class AWSProfileEditorDialog extends JDialog
{

    protected JTextField nameTextField;
    protected JTextField keyIdTextField;
    protected JTextField secretKeyTextField;
    protected JTextField regionTextField;
    protected JTextField serviceTextField;

    // Assume role fields
    protected JCheckBox assumeRoleCheckbox;
    protected JTextField roleArnTextField;
    protected JTextField sessionNameTextField;
    protected JTextField externalIdTextField;

    protected JButton okButton;
    protected JLabel statusLabel;

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
        final int TEXT_FIELD_WIDTH = 40;

        // panel for required fields
        JPanel basicPanel = new JPanel(new GridBagLayout());
        basicPanel.setBorder(new TitledBorder("Credentials"));
        basicPanel.add(new JLabel("Name"), newConstraint(0, 0, GridBagConstraints.LINE_START));
        this.nameTextField = new JTextField("", TEXT_FIELD_WIDTH);
        basicPanel.add(nameTextField, newConstraint(1, 0));
        basicPanel.add(new JLabel("KeyId"), newConstraint(0, 1, GridBagConstraints.LINE_START));
        this.keyIdTextField = new JTextField("", TEXT_FIELD_WIDTH);
        basicPanel.add(keyIdTextField, newConstraint(1, 1));
        basicPanel.add(new JLabel("SecretKey"), newConstraint(0, 2, GridBagConstraints.LINE_START));
        this.secretKeyTextField = new JTextField("", TEXT_FIELD_WIDTH);
        basicPanel.add(secretKeyTextField, newConstraint(1, 2));
        basicPanel.add(new JLabel("Region"), newConstraint(0, 3, GridBagConstraints.LINE_START));
        this.regionTextField = new OptionalJTextField("", TEXT_FIELD_WIDTH);
        basicPanel.add(regionTextField, newConstraint(1, 3));
        basicPanel.add(new JLabel("Service"), newConstraint(0, 4, GridBagConstraints.LINE_START));
        this.serviceTextField = new OptionalJTextField("", TEXT_FIELD_WIDTH);
        basicPanel.add(serviceTextField, newConstraint(1, 4));
        outerPanel.add(basicPanel, newConstraint(0, 0, GridBagConstraints.LINE_START));

        // panel for assume role fields
        this.assumeRoleCheckbox = new JCheckBox("Assume a role", false);
        outerPanel.add(assumeRoleCheckbox, newConstraint(0, 1, GridBagConstraints.LINE_START));
        JPanel rolePanel = new JPanel(new GridBagLayout());
        rolePanel.setBorder(new TitledBorder("Role"));
        rolePanel.add(new JLabel("RoleArn"), newConstraint(0, 0, GridBagConstraints.LINE_START));
        this.roleArnTextField = new JTextField("", TEXT_FIELD_WIDTH-2);
        rolePanel.add(this.roleArnTextField, newConstraint(1, 0));
        rolePanel.add(new JLabel("SessionName"), newConstraint(0, 2, GridBagConstraints.LINE_START));
        this.sessionNameTextField = new OptionalJTextField("", TEXT_FIELD_WIDTH-2);
        rolePanel.add(this.sessionNameTextField, newConstraint(1, 2));
        rolePanel.add(new JLabel("ExternalId"), newConstraint(0, 1, GridBagConstraints.LINE_START));
        this.externalIdTextField = new OptionalJTextField("", TEXT_FIELD_WIDTH-2);
        rolePanel.add(this.externalIdTextField, newConstraint(1, 1));
        outerPanel.add(rolePanel, newConstraint(0, 2, GridBagConstraints.LINE_START));

        statusLabel = new JLabel("<html><i>Ok to submit</i></html>");
        statusLabel.setForeground(burp.textOrange);
        this.okButton = new JButton("Ok");
        JButton cancelButton = new JButton("Cancel");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        outerPanel.add(statusLabel, newConstraint(0, 3, 2, 1));
        outerPanel.add(buttonPanel, newConstraint(0, 4, 2, 1));

        this.assumeRoleCheckbox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                rolePanel.setVisible(assumeRoleCheckbox.isSelected());
                pack();
            }
        });

        cancelButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                setVisible(false);
                dispose();
            }
        });
        okButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                AWSAssumeRole assumeRole = null;
                try {
                    if (profile != null && !roleArnTextField.getText().equals("")) {
                        // edit dialog
                        if (profile.getAssumeRole() != null) {
                            assumeRole = new AWSAssumeRole.Builder(profile.getAssumeRole())
                                    .withRoleArn(roleArnTextField.getText())
                                    .tryExternalId(externalIdTextField.getText())
                                    .tryRoleSessionName(sessionNameTextField.getText())
                                    .build();
                        }
                        else {
                            // no previous role arn
                            assumeRole = new AWSAssumeRole.Builder(roleArnTextField.getText(), burp)
                                    .tryExternalId(externalIdTextField.getText())
                                    .tryRoleSessionName(sessionNameTextField.getText())
                                    .build();
                        }
                    }

                    AWSProfile newProfile = new AWSProfile.Builder(nameTextField.getText(), keyIdTextField.getText(), secretKeyTextField.getText())
                            .withRegion(regionTextField.getText())
                            .withService(serviceTextField.getText())
                            .withAssumeRoleEnabled(assumeRoleCheckbox.isSelected())
                            .withAssumeRole(assumeRole)
                            .build();

                    burp.updateProfile(profile, newProfile);
                    setVisible(false);
                    dispose();
                } catch (IllegalArgumentException exc) {
                    setStatusLabel("Invalid settings: " + exc.getMessage());
                }
            }
        });

        // populate fields with existing profile for an "edit" dialog.
        applyProfile(profile);
        rolePanel.setVisible(assumeRoleCheckbox.isSelected());

        add(outerPanel);
        pack();
        // setting to burp.getUiComponent() is not sufficient for dialogs popped outside the SigV4 tab.
        setLocationRelativeTo(SwingUtilities.getWindowAncestor(burp.getUiComponent()));
    }

    protected void setStatusLabel(final String message)
    {
        statusLabel.setText(
                String.format("<html><div style='width: 400px'><i>%s</i></div></html>",
                        message.replace("<", "&lt;").replace(">", "&gt;")));
        pack();
    }

    protected void applyProfile(final AWSProfile profile)
    {
        if (profile != null) {
            nameTextField.setText(profile.getName());
            keyIdTextField.setText(profile.getAccessKeyId());
            secretKeyTextField.setText(profile.getSecretKey());
            regionTextField.setText(profile.getRegion());
            serviceTextField.setText(profile.getService());
            assumeRoleCheckbox.setSelected(profile.getAssumeRoleEnabled());
            if (profile.getAssumeRole() != null) {
                roleArnTextField.setText(profile.getAssumeRole().getRoleArn());
                sessionNameTextField.setText(profile.getAssumeRole().getSessionName());
                externalIdTextField.setText(profile.getAssumeRole().getExternalId());
            }
        }
    }
}


/*
This class implements a JTextField with "Optional" hint text when no user input is present.
 */
class OptionalJTextField extends JTextField implements FocusListener
{
    private Font defaultFont;
    private Color defaultForegroundColor;
    private Color optionalForegroundColor;

    public OptionalJTextField(String content, int width) {
        super(content, width);
        init();
    }

    public OptionalJTextField(String content) {
        super(content);
        init();
    }

    void init() {
        defaultFont = getFont();
        addFocusListener(this);
        defaultForegroundColor = getForeground();
        optionalForegroundColor = new Color(0xbb, 0xbb, 0xbb);
        if (super.getText().equals("")) {
            setHintText();
        }
    }

    @Override
    public String getText() {
        // make sure we don't return "Optional" when these fields are saved
        if (getFont().isItalic()) {
            return "";
        }
        return super.getText();
    }

    @Override
    public void setText(final String text) {
        if (!text.equals("")) {
            setUserText(text);
        }
    }

    private void setHintText() {
        setFont(new Font(defaultFont.getFamily(), Font.ITALIC, defaultFont.getSize()));
        setForeground(optionalForegroundColor);
        super.setText("Optional");
    }

    private void setUserText(final String text) {
        setFont(defaultFont);
        setForeground(defaultForegroundColor);
        super.setText(text);
    }

    @Override
    public void focusGained(FocusEvent focusEvent) {
        if (getFont().isItalic()) {
            setUserText("");
        }
    }

    @Override
    public void focusLost(FocusEvent focusEvent) {
        if (super.getText().equals("")) {
            setHintText();
        }
    }
}
