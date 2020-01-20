package burp;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.nio.file.Path;
import java.time.Instant;

public class AWSProfileEditorDialog extends JDialog
{
    static final Color disabledColor = new Color(161, 161, 161);

    protected JTextField nameTextField;
    protected JTextField profileKeyIdTextField;
    protected JTextField regionTextField;
    protected JTextField serviceTextField;

    protected JButton okButton;
    protected JPanel providerPanel;

    // static creds fields
    private JRadioButton staticProviderRadioButton;
    private JTextField accessKeyIdTextField;
    protected JTextField secretKeyTextField;
    protected JTextField sessionTokenTextField;

    // Assume role fields
    private JRadioButton assumeRoleProviderRadioButton;
    private JTextField roleArnTextField;
    private JTextField sessionNameTextField;
    private JTextField externalIdTextField;

    // Http provider
    private JRadioButton httpProviderRadioButton;
    private JTextField httpProviderUrlField;
    private JTextField httpProviderCaPathField;

    private JLabel statusLabel;

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
        int outerPanelY = 0;
        int providerPanelY = 0;

        // panel for required fields
        JPanel basicPanel = new JPanel(new GridBagLayout());
        basicPanel.setBorder(new TitledBorder("Profile"));
        basicPanel.add(new JLabel("Name"), newConstraint(0, 0, GridBagConstraints.LINE_START));
        this.nameTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH, "Required");
        basicPanel.add(nameTextField, newConstraint(1, 0));
        basicPanel.add(new JLabel("KeyId"), newConstraint(0, 1, GridBagConstraints.LINE_START));
        this.profileKeyIdTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH, "Required");
        this.profileKeyIdTextField.setToolTipText("Look for this AccessKeyId in a request to automatically select this profile");
        basicPanel.add(profileKeyIdTextField, newConstraint(1, 1));
        basicPanel.add(new JLabel("Region"), newConstraint(0, 2, GridBagConstraints.LINE_START));
        this.regionTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH, "Optional");
        basicPanel.add(regionTextField, newConstraint(1, 2));
        basicPanel.add(new JLabel("Service"), newConstraint(0, 3, GridBagConstraints.LINE_START));
        this.serviceTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH, "Optional");
        basicPanel.add(serviceTextField, newConstraint(1, 3));
        outerPanel.add(basicPanel, newConstraint(0, outerPanelY++, GridBagConstraints.LINE_START));

        providerPanel = new JPanel(new GridBagLayout());

        // RadioButton panel for selecting credential provider
        staticProviderRadioButton = new JRadioButton("Static credentials");
        staticProviderRadioButton.setSelected(true); //default
        assumeRoleProviderRadioButton = new JRadioButton("AssumeRole");
        httpProviderRadioButton = new JRadioButton("HttpGet");
        ButtonGroup providerButtonGroup = new ButtonGroup();
        providerButtonGroup.add(staticProviderRadioButton);
        providerButtonGroup.add(assumeRoleProviderRadioButton);
        providerButtonGroup.add(httpProviderRadioButton);
        JPanel providerButtonPanel = new JPanel(new FlowLayout());
        providerButtonPanel.add(staticProviderRadioButton);
        providerButtonPanel.add(assumeRoleProviderRadioButton);
        providerButtonPanel.add(httpProviderRadioButton);
        providerPanel.add(providerButtonPanel, newConstraint(0, providerPanelY++, GridBagConstraints.LINE_START));

        // panel for static credentials
        JPanel staticCredentialsPanel = new JPanel(new GridBagLayout());
        staticCredentialsPanel.setBorder(new TitledBorder("Credentials"));
        staticCredentialsPanel.add(new JLabel("AccessKeyId"), newConstraint(0, 0, GridBagConstraints.LINE_START));
        this.accessKeyIdTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH-3, "Required");
        staticCredentialsPanel.add(accessKeyIdTextField, newConstraint(1, 0));
        staticCredentialsPanel.add(new JLabel("SecretKey"), newConstraint(0, 1, GridBagConstraints.LINE_START));
        this.secretKeyTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH-3, "Required");
        staticCredentialsPanel.add(secretKeyTextField, newConstraint(1, 1));
        staticCredentialsPanel.add(new JLabel("SessionToken"), newConstraint(0, 2, GridBagConstraints.LINE_START));
        this.sessionTokenTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH-3, "Optional");
        staticCredentialsPanel.add(sessionTokenTextField, newConstraint(1, 2));
        providerPanel.add(staticCredentialsPanel, newConstraint(0, providerPanelY++, GridBagConstraints.LINE_START));

        // panel for assume role fields
        JPanel rolePanel = new JPanel(new GridBagLayout());
        rolePanel.setBorder(new TitledBorder("Role"));
        rolePanel.add(new JLabel("RoleArn"), newConstraint(0, 0, GridBagConstraints.LINE_START));
        this.roleArnTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH-3, "Required");
        rolePanel.add(this.roleArnTextField, newConstraint(1, 0));
        rolePanel.add(new JLabel("SessionName"), newConstraint(0, 1, GridBagConstraints.LINE_START));
        this.sessionNameTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH-3, "Optional");
        rolePanel.add(this.sessionNameTextField, newConstraint(1, 1));
        rolePanel.add(new JLabel("ExternalId"), newConstraint(0, 2, GridBagConstraints.LINE_START));
        this.externalIdTextField = new JTextFieldHint("", TEXT_FIELD_WIDTH-3, "Optional");
        rolePanel.add(this.externalIdTextField, newConstraint(1, 2));
        providerPanel.add(rolePanel, newConstraint(0, providerPanelY++, GridBagConstraints.LINE_START));

        // panel for http provided creds
        JPanel httpPanel = new JPanel(new GridBagLayout());
        httpPanel.setBorder(new TitledBorder("Http Credentials"));
        httpPanel.add(new JLabel("GET Url"), newConstraint(0, 0, GridBagConstraints.LINE_START));
        this.httpProviderUrlField = new JTextFieldHint("", TEXT_FIELD_WIDTH-2, "Required");
        httpPanel.add(this.httpProviderUrlField, newConstraint(1, 0));
        JButton httpProviderCaPathButton = new JButton("CA Path");
        httpPanel.add(httpProviderCaPathButton, newConstraint(0, 1, GridBagConstraints.LINE_START));
        this.httpProviderCaPathField = new JTextFieldHint("", TEXT_FIELD_WIDTH-2, "Optional");
        this.httpProviderCaPathField.setEditable(false);
        this.httpProviderCaPathField.setFocusable(false);
        httpPanel.add(this.httpProviderCaPathField, newConstraint(1, 1, GridBagConstraints.LINE_START));
        providerPanel.add(httpPanel, newConstraint(0, providerPanelY++, GridBagConstraints.LINE_START));

        outerPanel.add(providerPanel, newConstraint(0, outerPanelY++, GridBagConstraints.LINE_START));
        statusLabel = new JLabel("<html><i>Ok to submit</i></html>");
        statusLabel.setForeground(burp.textOrange);
        okButton = new JButton("Ok");
        JButton cancelButton = new JButton("Cancel");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        outerPanel.add(statusLabel, newConstraint(0, outerPanelY++, 2, 1));
        outerPanel.add(buttonPanel, newConstraint(0, outerPanelY++, 2, 1));

        ActionListener providerButtonActionListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                staticCredentialsPanel.setVisible(staticProviderRadioButton.isSelected());
                rolePanel.setVisible(assumeRoleProviderRadioButton.isSelected());
                httpPanel.setVisible(httpProviderRadioButton.isSelected());
                if (actionEvent.getSource().equals(assumeRoleProviderRadioButton)) {
                    staticCredentialsPanel.setVisible(true);
                }
                pack();
            }
        };
        this.staticProviderRadioButton.addActionListener(providerButtonActionListener);
        this.assumeRoleProviderRadioButton.addActionListener(providerButtonActionListener);
        this.httpProviderRadioButton.addActionListener(providerButtonActionListener);

        httpProviderCaPathButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                JFileChooser chooser = new JFileChooser(System.getProperty("user.home"));
                chooser.setFileHidingEnabled(false);
                if (chooser.showOpenDialog(burp.getUiComponent()) == JFileChooser.APPROVE_OPTION) {
                    httpProviderCaPathField.setText(chooser.getSelectedFile().getPath());
                }
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
                final String accessKeyId = accessKeyIdTextField.getText();
                final String secretKey = secretKeyTextField.getText();
                final String sessionToken = sessionTokenTextField.getText();

                try {
                    if (profile != null && !roleArnTextField.getText().equals("")) {
                        // edit dialog
                        final AWSPermanentCredential permanentCredential = new AWSPermanentCredential(accessKeyIdTextField.getText(), secretKeyTextField.getText());
                        if (profile.getAssumeRole() != null) {
                            assumeRole = new AWSAssumeRole.Builder(profile.getAssumeRole())
                                    .withRoleArn(roleArnTextField.getText())
                                    .withCredential(permanentCredential)
                                    .tryExternalId(externalIdTextField.getText())
                                    .tryRoleSessionName(sessionNameTextField.getText())
                                    .build();
                        }
                        else {
                            assumeRole = new AWSAssumeRole.Builder(roleArnTextField.getText(), permanentCredential)
                                    .tryExternalId(externalIdTextField.getText())
                                    .tryRoleSessionName(sessionNameTextField.getText())
                                    .build();
                        }
                    }

                    AWSProfile.Builder newProfileBuilder = new AWSProfile.Builder(nameTextField.getText(), profileKeyIdTextField.getText())
                            .withRegion(regionTextField.getText())
                            .withService(serviceTextField.getText());

                    if (!httpProviderUrlField.getText().equals("") || !httpProviderCaPathField.getText().equals("")) {
                        newProfileBuilder.withCredentialProvider(new AWSHttpProvider(httpProviderUrlField.getText(), httpProviderCaPathField.getText()),
                                httpProviderRadioButton.isSelected() ? AWSProfile.DEFAULT_HTTP_PRIORITY : AWSProfile.DISABLED_PRIORITY);
                    }

                    if (assumeRole != null)
                        newProfileBuilder.withCredentialProvider(assumeRole, assumeRoleProviderRadioButton.isSelected() ? AWSProfile.DEFAULT_ASSUMEROLE_PRIORITY : AWSProfile.DISABLED_PRIORITY);

                    // if any cred fields are specified, attempt to use them.
                    if (!accessKeyId.equals("") || !secretKey.equals("") || !sessionToken.equals("")) {
                        AWSCredential credential = new AWSPermanentCredential(accessKeyIdTextField.getText(), secretKeyTextField.getText());
                        if (!sessionToken.equals(""))
                            credential = new AWSTemporaryCredential(accessKeyId, secretKey, sessionToken, Instant.now().getEpochSecond() + 900);
                        newProfileBuilder.withCredentialProvider(new AWSStaticCredentialProvider(credential), AWSProfile.DEFAULT_STATIC_PRIORITY);
                    }

                    final AWSProfile newProfile = newProfileBuilder.build();
                    if (newProfile.getCredentialProviderCount() <= 0) {
                        throw new IllegalArgumentException("Must provide at least 1 authentication method");
                    }
                    burp.updateProfile(profile, newProfile);
                    setVisible(false);
                    dispose();
                } catch (IllegalArgumentException exc) {
                    setStatusLabel("Invalid settings: " + exc.getMessage());
                }
            }
        });

        // populate fields with existing profile for an "edit" dialog.
        staticCredentialsPanel.setVisible(staticProviderRadioButton.isSelected());
        httpPanel.setVisible(httpProviderRadioButton.isSelected());
        rolePanel.setVisible(assumeRoleProviderRadioButton.isSelected());
        applyProfile(profile);

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
            profileKeyIdTextField.setText(profile.getAccessKeyId());
            regionTextField.setText(profile.getRegion());
            serviceTextField.setText(profile.getService());
            if (profile.getStaticCredentialProvider() != null) {
                AWSCredential credential = profile.getStaticCredentialProvider().getCredential();
                accessKeyIdTextField.setText(credential.getAccessKeyId());
                secretKeyTextField.setText(credential.getSecretKey());
                if (credential.isTemporary()) {
                    sessionTokenTextField.setText(((AWSTemporaryCredential)credential).getSessionToken());
                }
                if (profile.getStaticCredentialProviderPriority() >= 0) {
                    staticProviderRadioButton.doClick();
                }
            }
            if (profile.getAssumeRole() != null) {
                roleArnTextField.setText(profile.getAssumeRole().getRoleArn());
                sessionNameTextField.setText(profile.getAssumeRole().getSessionName());
                externalIdTextField.setText(profile.getAssumeRole().getExternalId());
                // initialize static creds as well
                accessKeyIdTextField.setText(profile.getAssumeRole().getPermanentCredential().getAccessKeyId());
                secretKeyTextField.setText(profile.getAssumeRole().getPermanentCredential().getSecretKey());
                if (profile.getAssumeRolePriority() >= 0) {
                    assumeRoleProviderRadioButton.doClick();
                }
            }
            if (profile.getHttpCredentialProvider() != null) {
                httpProviderUrlField.setText(profile.getHttpCredentialProvider().getUrl().toString());
                final Path caPath = profile.getHttpCredentialProvider().getCaBundlePath();
                if (caPath != null) {
                    httpProviderCaPathField.setText(caPath.toString());
                }
                if (profile.getHttpCredentialProviderPriority() >= 0) {
                    httpProviderRadioButton.doClick();
                }
            }
        }
    }
}


/*
This class implements a JTextField with "Optional" hint text when no user input is present.
 */
class JTextFieldHint extends JTextField implements FocusListener
{
    private Font defaultFont;
    private Color defaultForegroundColor;
    private Color hintForegroundColor = AWSProfileEditorDialog.disabledColor;;
    private String hintText;

    public JTextFieldHint(String content, int width, String hintText) {
        super(content, width);
        this.hintText = hintText;
        init();
    }

    void init() {
        defaultFont = getFont();
        addFocusListener(this);
        defaultForegroundColor = getForeground();
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
        setForeground(hintForegroundColor);
        super.setText(hintText);
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

