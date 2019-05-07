package burp;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.util.List;


public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IExtensionStateListener, IMessageEditorTabFactory
{
    private static final String SETTING_PROFILES = "SerializedProfileList";
    private static final String SETTING_PERSISTENT_PROFILES = "PersistentProfiles";
    private static final String SETTING_EXTENSION_ENABLED = "ExtensionEnabled";
    private static final String SETTING_DEFAULT_PROFILE_NAME = "DefaultProfileName";
    private static final String SETTING_LOG_LEVEL = "LogLevel";
    private static final String SETTING_CUSTOM_HEADERS = "CustomHeaders";
    private static final String SETTING_INSCOPE_ONLY = "InScopeOnly";

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private HashMap<String, AWSProfile> profileKeyIdMap; // map accessKeyId to profile
    private HashMap<String, AWSProfile> profileNameMap; // map accessKeyId to profile
    private LogWriter logger;

    private JPanel panel1;
    private JComboBox profileComboBox;
    private JTextField nameTextField;
    private JTextField accessKeyIdTextField;
    private JTextField secretKeyTextField;
    private JTextField regionTextField;
    private JTextField serviceTextField;
    private JCheckBox regionCheckBox;
    private JCheckBox serviceCheckBox;
    private JButton saveProfileButton;
    private JButton deleteProfileButton;
    private JButton importProfilesButton;
    private JLabel statusLabel;
    private JButton makeDefaultButton;
    private JCheckBox enabledCheckBox;
    private JComboBox defaultProfileComboBox;
    private JComboBox logLevelComboBox;
    private JCheckBox persistProfilesCheckBox;
    private JTextArea customHeadersTextArea;
    private JCheckBox inScopeOnlyCheckBox;
    private AWSContextMenu contextMenu;

    public boolean isEnabled()
    {
        return this.enabledCheckBox.isSelected();
    }

    public BurpExtender() {};

    @Override
    public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks)
    {
        this.helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        callbacks.setExtensionName("AWSig");
        callbacks.registerExtensionStateListener(this);

        this.logger = new LogWriter(callbacks.getStdout(), callbacks.getStderr(), LogWriter.ERROR_LEVEL);
        String setting = this.callbacks.loadExtensionSetting(SETTING_LOG_LEVEL);
        if (setting != null) {
            logger.setLevel(Integer.parseInt(setting));
        }

        this.profileKeyIdMap = new HashMap<>();
        this.profileNameMap = new HashMap<>();

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                callbacks.addSuiteTab(BurpExtender.this);
                callbacks.registerHttpListener(BurpExtender.this);

                contextMenu = new AWSContextMenu(BurpExtender.this);
                callbacks.registerContextMenuFactory(contextMenu);
                callbacks.registerMessageEditorTabFactory(BurpExtender.this);

                setupPanel();
                loadExtensionSettings();

                logger.info("Loaded AWSig");
            }
        });
    }

    private void saveExtensionSettings()
    {
        ArrayList<AWSProfile> awsProfiles = new ArrayList<>();
        if (this.persistProfilesCheckBox.isSelected()) {
            for (final String name : this.profileNameMap.keySet()) {
                awsProfiles.add(this.profileNameMap.get(name));
            }
        }
        try {
            ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
            ObjectOutputStream objectOut = new ObjectOutputStream(bytesOut);
            objectOut.writeObject(awsProfiles);
            objectOut.close();
            final String serializedProfileList = this.helpers.base64Encode(bytesOut.toByteArray());
            this.callbacks.saveExtensionSetting(SETTING_PROFILES, serializedProfileList);
            logger.info(String.format("Saved %d profile(s)", awsProfiles.size()));
        } catch (Exception exc) {
            logger.error("Failed to save AWS profiles");
        }

        this.callbacks.saveExtensionSetting(SETTING_PERSISTENT_PROFILES, this.persistProfilesCheckBox.isSelected() ? "true" : "false");
        this.callbacks.saveExtensionSetting(SETTING_EXTENSION_ENABLED, this.enabledCheckBox.isSelected() ? "true" : "false");
        this.callbacks.saveExtensionSetting(SETTING_DEFAULT_PROFILE_NAME, this.getDefaultProfileName());
        this.callbacks.saveExtensionSetting(SETTING_LOG_LEVEL, Integer.toString(logger.getLevel()));
        this.callbacks.saveExtensionSetting(SETTING_CUSTOM_HEADERS, String.join("\n", getCustomHeadersFromUI()));
        this.callbacks.saveExtensionSetting(SETTING_INSCOPE_ONLY, this.inScopeOnlyCheckBox.isSelected() ? "true" : "false");
    }

    private void loadExtensionSettings()
    {
        try {
            final String serializedProfileListBase64 = callbacks.loadExtensionSetting(SETTING_PROFILES);
            if (serializedProfileListBase64 != null) {
                final byte[] serializedProfileList = helpers.base64Decode(serializedProfileListBase64);
                ObjectInputStream objectIn = new ObjectInputStream(new ByteArrayInputStream(serializedProfileList));
                ArrayList<AWSProfile> profileList = (ArrayList<AWSProfile>) objectIn.readObject();
                objectIn.close();
                for (final AWSProfile profile : profileList) {
                    addProfile(profile);
                }
                logger.info(String.format("Loaded %s profile(s)", profileList.size()));
            }
            else {
                logger.debug("No saved profiles to load");
            }
        } catch (Exception exc) {
            logger.error("Failed to load saved profiles");
        }

        String setting = this.callbacks.loadExtensionSetting(SETTING_PERSISTENT_PROFILES);
        if ((setting != null) && setting.toLowerCase().equals("true")) {
            this.persistProfilesCheckBox.setSelected(true);
        }
        setting = this.callbacks.loadExtensionSetting(SETTING_EXTENSION_ENABLED);
        if ((setting == null) || setting.toLowerCase().equals("true")) {
            this.enabledCheckBox.setSelected(true);
        }
        setDefaultProfileName(this.callbacks.loadExtensionSetting(SETTING_DEFAULT_PROFILE_NAME));
        final String customHeaderText = this.callbacks.loadExtensionSetting(SETTING_CUSTOM_HEADERS);
        if (customHeaderText != null) {
            this.customHeadersTextArea.setText(customHeaderText);
        }
        setting = this.callbacks.loadExtensionSetting(SETTING_INSCOPE_ONLY);
        if ((setting != null) && setting.toLowerCase().equals("true")) {
            this.inScopeOnlyCheckBox.setSelected(true);
        }
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new AWSMessageEditorTab(controller, editable, this, this.callbacks, this.logger);
    }

    @Override
    public void extensionUnloaded()
    {
        saveExtensionSettings();
        logger.info("Unloading AWSig");
    }

    public List<JMenuItem> getContextMenuItems() {
        JMenu menu = new JMenu("AWSig");

        // add disable item
        JRadioButtonMenuItem item = new JRadioButtonMenuItem("Disable AWSig", !isEnabled());
        item.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                enabledCheckBox.setSelected(false);
            }
        });
        menu.add(item);

        ArrayList<String> profileList = new ArrayList<>(this.profileNameMap.keySet());
        profileList.add(0, ""); // no default option

        for (final String name : profileList) {
            item = new JRadioButtonMenuItem(name, isEnabled() && name.equals(getDefaultProfileName()));
            item.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    JRadioButtonMenuItem item = (JRadioButtonMenuItem)actionEvent.getSource();
                    setDefaultProfileName(item.getText());
                    enabledCheckBox.setSelected(true);
                }
            });
            menu.add(item);
        }

        ArrayList<JMenuItem> list = new ArrayList<>();
        list.add(menu);
        return list;
    }

    @Override
    public String getTabCaption()
    {
        return "SigV4";
    }


    private Component buildUiTab()
    {
        JPanel outerPanel = new JPanel();

        outerPanel.setLayout(new GridBagLayout());

        // global settings, checkboxes
        JPanel checkBoxPanel = new JPanel();
        JCheckBox signingEnabledCheckBox = new JCheckBox("Signing Enabled");
        signingEnabledCheckBox.setToolTipText("Disable SigV4 signing");
        JCheckBox inScopeOnlyCheckBox = new JCheckBox("In-scope Only");
        inScopeOnlyCheckBox.setToolTipText("Sign in-scope requests only");
        JCheckBox persistProfilesCheckBox = new JCheckBox("Persist Profiles");
        persistProfilesCheckBox.setToolTipText("Save profiles, including keys, in Burp settings store");
        checkBoxPanel.setBorder(new TitledBorder("Global Options"));
        checkBoxPanel.add(signingEnabledCheckBox);
        checkBoxPanel.add(inScopeOnlyCheckBox);
        checkBoxPanel.add(persistProfilesCheckBox);

        // profiles table
        JPanel profilePanel = new JPanel();
        JButton addProfileButton = new JButton("Add");
        JButton editProfileButton = new JButton("Edit");
        JButton removeProfileButton = new JButton("Remove");
        JButton importProfileButton = new JButton("Import");
        JPanel profileButtonPanel = new JPanel();
        profileButtonPanel.setLayout(new GridLayout(4, 1));
        profileButtonPanel.add(addProfileButton);
        profileButtonPanel.add(editProfileButton);
        profileButtonPanel.add(removeProfileButton);
        profileButtonPanel.add(importProfileButton);

        String[] profileColumnNames = { "Name", "KeyId", "SecretKey", "Region", "Service" };
        JTable profileTable = new JTable(new DefaultTableModel(profileColumnNames, 0));

        JScrollPane profileScrollPane = new JScrollPane(profileTable);
        profileScrollPane.setPreferredSize(new Dimension(1000, 200));

        profilePanel.setBorder(new TitledBorder("AWS Profiles"));
        profilePanel.add(profileButtonPanel);
        profilePanel.add(profileScrollPane);

        // custom signed headers table
        JPanel customHeadersPanel = new JPanel();
        JPanel customHeadersButtonPanel = new JPanel();
        customHeadersButtonPanel.setLayout(new GridLayout(3, 1));
        JButton addHeaderButton = new JButton("Add");
        JButton editHeaderButton = new JButton("Edit");
        JButton removeHeaderButton = new JButton("Remove");
        customHeadersButtonPanel.add(addHeaderButton);
        customHeadersButtonPanel.add(editHeaderButton);
        customHeadersButtonPanel.add(removeHeaderButton);

        String[] headersColumnNames = { "Name", "Value" };
        JTable headersTable = new JTable(new Object[0][], headersColumnNames);
        JScrollPane headersScrollPane = new JScrollPane(headersTable);
        headersScrollPane.setPreferredSize(new Dimension(1000, 200));

        customHeadersPanel.setBorder(new TitledBorder("Custom Signed Headers"));
        customHeadersPanel.add(customHeadersButtonPanel);
        customHeadersPanel.add(headersScrollPane);

        // put it all together
        GridBagConstraints c1 = new GridBagConstraints();
        c1.gridy = 0;
        c1.anchor = GridBagConstraints.FIRST_LINE_START;
        GridBagConstraints c2 = new GridBagConstraints();
        c2.gridy = 1;
        c2.anchor = GridBagConstraints.FIRST_LINE_START;
        GridBagConstraints c3 = new GridBagConstraints();
        c3.gridy = 2;
        c3.anchor = GridBagConstraints.FIRST_LINE_START;

        outerPanel.add(checkBoxPanel, c1);
        outerPanel.add(profilePanel, c2);
        outerPanel.add(customHeadersPanel, c3);

        JPanel outerOuterPanel = new JPanel();
        GridBagConstraints cc = new GridBagConstraints();
        cc.anchor = GridBagConstraints.FIRST_LINE_START;
        cc.gridx = 0;
        outerOuterPanel.add(outerPanel);
        this.callbacks.customizeUiComponent(outerOuterPanel);

        return outerOuterPanel;
    }

    @Override
    public Component getUiComponent() {
        //return panel1;
        return buildUiTab();
    }

    private AWSProfile profileFromCurrentForm()
    {
        return new AWSProfile(nameTextField.getText().trim(), accessKeyIdTextField.getText().trim(),
            secretKeyTextField.getText().trim(), regionTextField.getText().trim(), regionCheckBox.isSelected(), serviceTextField.getText().trim(),
            serviceCheckBox.isSelected());
    }

    private void setupPanel()
    {
        this.importProfilesButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                importProfiles();
            }
        });

        this.profileComboBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                updateForm((String)profileComboBox.getSelectedItem());
            }
        });

        this.saveProfileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                AWSProfile profile = profileFromCurrentForm();
                if (addProfile(profile)) {
                    updateForm(profile.name);
                }
            }
        });

        this.makeDefaultButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                final String name = (String)profileComboBox.getSelectedItem();
                setDefaultProfileName(name);
            }
        });

        this.deleteProfileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                deleteProfile(profileFromCurrentForm());
            }
        });

        class LogLevelComboBoxItem
        {
            final private int logLevel;
            final private String levelName;
            public LogLevelComboBoxItem(final int logLevel)
            {
                this.logLevel = logLevel;
                this.levelName = LogWriter.levelNameFromInt(logLevel);
            }

            @Override
            public String toString() { return this.levelName; }
        }
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.DEBUG_LEVEL));
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.INFO_LEVEL));
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.ERROR_LEVEL));
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.FATAL_LEVEL));
        this.logLevelComboBox.setSelectedIndex(logger.getLevel());

        this.logLevelComboBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                logger.setLevel(((LogLevelComboBoxItem)logLevelComboBox.getSelectedItem()).logLevel);
            }
        });
    }

    // display status message in UI
    private void updateStatus(final String status)
    {
        this.statusLabel.setText(status);
    }

    /*
    call this when profile list changes
    */
    private void updateComboBox()
    {
        this.profileComboBox.removeAllItems();
        for (final String name : this.profileNameMap.keySet()) {
            this.profileComboBox.addItem(name);
        }

        // update default profile combobox
        final String defaultProfileName = (String)this.defaultProfileComboBox.getSelectedItem();
        this.defaultProfileComboBox.removeAllItems();
        this.defaultProfileComboBox.addItem(""); // disabled
        for (final String name : this.profileNameMap.keySet()) {
            this.defaultProfileComboBox.addItem(name);
        }
        setDefaultProfileName(defaultProfileName);
        updateForm(this.nameTextField.getText());
    }

    private void clearForm()
    {
        this.nameTextField.setText("");
        this.accessKeyIdTextField.setText("");
        this.secretKeyTextField.setText("");
        this.regionTextField.setText("");
        this.serviceTextField.setText("");

        this.regionCheckBox.setSelected(false);
        this.serviceCheckBox.setSelected(false);
    }

    /*
    fill form with profile of given name
    */
    private void updateForm(final String name)
    {
        AWSProfile profile = this.profileNameMap.get(name);
        if (profile == null) {
            clearForm();
            return;
        }

        for (int i = 0; i < this.profileComboBox.getItemCount(); i++) {
            if (this.profileComboBox.getItemAt(i).equals(name)) {
                this.profileComboBox.setSelectedIndex(i);
                break;
            }
        }

        this.nameTextField.setText(profile.name);
        this.accessKeyIdTextField.setText(profile.accessKeyId);
        this.secretKeyTextField.setText(profile.secretKey);
        this.regionTextField.setText(profile.region);
        this.serviceTextField.setText(profile.service);

        this.regionCheckBox.setSelected(profile.regionAuto);
        this.serviceCheckBox.setSelected(profile.serviceAuto);
    }

    private boolean addProfile(AWSProfile profile)
    {
        if (profile.name.length() > 0) {
            AWSProfile p1 = this.profileNameMap.get(profile.name);
            AWSProfile p2 = this.profileKeyIdMap.get(profile.accessKeyId);
            if ((p2 != null) && (p1 == null)) {
                updateStatus("Profiles must have a unique accessKeyId");
                return false;
            }
            // for accessKeyId updates, clean up the old id
            if (p1 != null) {
                if (this.profileKeyIdMap.containsKey(p1.accessKeyId)) {
                    this.profileKeyIdMap.remove(p1.accessKeyId);
                }
            }
            this.profileKeyIdMap.put(profile.accessKeyId, profile);
            this.profileNameMap.put(profile.name, profile);
            updateComboBox();
            if (p1 == null) {
                updateStatus(String.format("Added profile '%s'", profile.name));
            }
            else {
                updateStatus(String.format("Saved profile '%s'", profile.name));
            }
            return true;
        }
        return false;
    }

    private void deleteProfile(AWSProfile profile)
    {
        if (this.profileNameMap.containsKey(profile.name)) {
            updateStatus(String.format("Deleted profile '%s'", profile.name));
        }
        this.profileKeyIdMap.remove(profile.accessKeyId);
        this.profileNameMap.remove(profile.name);
        updateComboBox();
    }

    private void importProfiles()
    {
        /*
        import creds from well-known path. if path does not exist, prompt user. last imported profile
        will become the default.
        */
        Path credPath = Paths.get(System.getProperty("user.home"),".aws", "credentials");
        if (!Files.exists(credPath)) {
            JFileChooser chooser = new JFileChooser(System.getProperty("user.home"));
            chooser.setFileHidingEnabled(false);
            if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                credPath = Paths.get(chooser.getSelectedFile().getPath());
            } else {
                return;
            }
        }
        logger.info("Importing AWS credentials from: " + credPath);

        int count = 0;
        for (AWSProfile profile : AWSProfile.fromCredentialPath(credPath)) {
            if (addProfile(profile)) {
                logger.info("Imported profile: "+profile);
                count += 1;
            }
        }

        // try to import creds from environment variables
        AWSProfile profile = AWSProfile.fromEnvironment();
        if (profile != null) {
            if (addProfile(profile)) {
                logger.info("Imported profile: "+profile);
                count += 1;
            }
        }
        updateStatus(String.format("Imported %d profiles", count));
    }

    /*
    Check if the request is for AWS. Can be POST or GET request.
    */
    public static boolean isAwsRequest(IRequestInfo request) {
        // all AWS requests require x-amz-date either in the query string or as a header. Date can be used but is not unique enough.
        // Consider adding additional check for Authorization header or X-Amz-Credential query string param.
        // https://docs.aws.amazon.com/general/latest/gr/sigv4-date-handling.html
        for (String header : request.getHeaders()) {
            if (header.toLowerCase().startsWith("x-amz-date:")) {
                return true;
            }
        }

        // check for query string parameters
        for (IParameter param : request.getParameters()) {
            if (param.getName().toLowerCase().equals("x-amz-date")) {
                return true;
            }
        }

        return false;
    }

    private void printHeaders(IRequestInfo request)
    {
        logger.debug("Request Parameters");
        for (IParameter param : request.getParameters()) {
            logger.debug(String.format("%s = %s", param.getName(), param.getValue()));
        }
        logger.debug("Request Headers");
        for (String header : request.getHeaders()) {
            logger.debug("+"+header);
        }
    }

    private String getDefaultProfileName()
    {
        String defaultProfileName = (String)this.defaultProfileComboBox.getSelectedItem();
        if (defaultProfileName == null) {
            defaultProfileName = "";
        }
        return defaultProfileName;
    }

    private boolean setDefaultProfileName(final String defaultProfileName)
    {
        if (defaultProfileName != null) {
            for (int i = 0; i < this.defaultProfileComboBox.getItemCount(); i++) {
                if (this.defaultProfileComboBox.getItemAt(i).equals(defaultProfileName)) {
                    this.defaultProfileComboBox.setSelectedIndex(i);
                    //updateStatus("Default profile changed.");
                    return true;
                }
            }
        }
        return false;
    }

    public AWSProfile getSigningProfile(final String requestAccessKeyId)
    {
        AWSProfile profile = this.profileNameMap.get(getDefaultProfileName());
        if (profile == null) {
            profile = this.profileKeyIdMap.get(requestAccessKeyId);
        }
        return profile;
    }

    /* get the additional headers specified in the UI */
    private ArrayList<String> getCustomHeadersFromUI()
    {
        ArrayList<String> headers = new ArrayList<>();
        for (String header : this.customHeadersTextArea.getText().split("[\\r\\n]+")) {
            header = header.trim();
            if (header.length() > 0) {
                headers.add(header);
            }
        }
        return headers;
    }

    /*
    apply settings to a signed request and return applied profile
     */
    public AWSProfile customizeSignedRequest(AWSSignedRequest signedRequest)
    {
        AWSProfile profile = getSigningProfile(signedRequest.getAccessKeyId());
        if (profile == null) {
            logger.error("No profile found for accessKeyId: " + signedRequest.getAccessKeyId());
            return null;
        }

        // add any user-specified, custom HTTP headers
        signedRequest.addSignedHeaders(getCustomHeadersFromUI());

        signedRequest.applyProfile(profile);
        return profile;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        if (messageIsRequest && enabledCheckBox.isSelected()) {
            IRequestInfo request = helpers.analyzeRequest(messageInfo);

            // check request scope
            if (this.inScopeOnlyCheckBox.isSelected() && !this.callbacks.isInScope(request.getUrl())) {
                logger.debug("Skipping out of scope request: "+request.getUrl());
                return;
            }

            if (isAwsRequest(request)) {

                // use default profile, if there is one. else, match profile based on access key id in the request
                AWSSignedRequest signedRequest = new AWSSignedRequest(messageInfo, this.helpers, this.logger);
                final AWSProfile profile = customizeSignedRequest(signedRequest);
                if (profile == null) {
                    logger.error("Failed to apply custom settings to signed request");
                    return;
                }

                byte[] requestBytes = signedRequest.getSignedRequestBytes();
                if (requestBytes != null) {
                    logger.info("Signed request with profile: "+profile);
                    messageInfo.setRequest(requestBytes);
                }
            }
        }
    }

}