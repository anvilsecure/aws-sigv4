package burp;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.util.*;
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

    private static final String NO_DEFAULT_PROFILE = "";

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private HashMap<String, AWSProfile> profileKeyIdMap; // map accessKeyId to profile
    private HashMap<String, AWSProfile> profileNameMap; // map accessKeyId to profile
    private LogWriter logger;
    private AWSContextMenu contextMenu;

    private JLabel statusLabel;
    private JCheckBox signingEnabledCheckBox;
    private JComboBox defaultProfileComboBox;
    private JComboBox logLevelComboBox;
    private JCheckBox persistProfilesCheckBox;
    private JCheckBox inScopeOnlyCheckBox;

    public JFrame outerFrame;
    private JPanel outerOuterPanel;
    private JTable profileTable;
    private JTable customHeadersTable;

    public BurpExtender() {};

    private Component buildUiTab()
    {
        JPanel outerPanel = new JPanel();
        outerPanel.setLayout(new GridBagLayout());

        // global settings, checkboxes
        JPanel globalSettingsPanel = new JPanel();
        globalSettingsPanel.setLayout(new GridLayout(2, 3));
        globalSettingsPanel.setBorder(new TitledBorder("Global Options"));
        JPanel checkBoxPanel = new JPanel();
        signingEnabledCheckBox = new JCheckBox("Signing Enabled");
        signingEnabledCheckBox.setToolTipText("Disable SigV4 signing");
        inScopeOnlyCheckBox = new JCheckBox("In-scope Only");
        inScopeOnlyCheckBox.setToolTipText("Sign in-scope requests only");
        persistProfilesCheckBox = new JCheckBox("Persist Profiles");
        persistProfilesCheckBox.setToolTipText("Save profiles, including keys, in Burp settings store");
        checkBoxPanel.add(signingEnabledCheckBox);
        checkBoxPanel.add(inScopeOnlyCheckBox);
        checkBoxPanel.add(persistProfilesCheckBox);
        JPanel settingsPanel = new JPanel();
        defaultProfileComboBox = new JComboBox();
        logLevelComboBox = new JComboBox();
        settingsPanel.add(new JLabel("Log Level"));
        settingsPanel.add(logLevelComboBox);
        settingsPanel.add(new JLabel("Default Profile"));
        settingsPanel.add(defaultProfileComboBox);
        globalSettingsPanel.add(checkBoxPanel);
        globalSettingsPanel.add(settingsPanel);

        // status label
        JPanel statusPanel = new JPanel();
        statusLabel = new JLabel();
        statusPanel.add(statusLabel);

        // profiles table
        JPanel profilePanel = new JPanel();
        JButton addProfileButton = new JButton("Add");
        JButton editProfileButton = new JButton("Edit");
        JButton removeProfileButton = new JButton("Remove");
        JButton makeDefaultButton = new JButton("Default");
        JButton importProfileButton = new JButton("Import");
        JPanel profileButtonPanel = new JPanel();
        profileButtonPanel.setLayout(new GridLayout(5, 1));
        profileButtonPanel.add(addProfileButton);
        profileButtonPanel.add(editProfileButton);
        profileButtonPanel.add(removeProfileButton);
        profileButtonPanel.add(makeDefaultButton);
        profileButtonPanel.add(importProfileButton);

        String[] profileColumnNames = { "Name", "KeyId", "SecretKey", "Region", "Service" };
        profileTable = new JTable(new DefaultTableModel(profileColumnNames, 0));

        JScrollPane profileScrollPane = new JScrollPane(profileTable);
        profileScrollPane.setPreferredSize(new Dimension(1000, 200));

        profilePanel.setBorder(new TitledBorder("AWS Profiles"));
        profilePanel.add(profileButtonPanel);
        profilePanel.add(profileScrollPane);

        // custom signed headers table
        JPanel customHeadersPanel = new JPanel();
        JPanel customHeadersButtonPanel = new JPanel();
        customHeadersButtonPanel.setLayout(new GridLayout(3, 1));
        JButton addCustomHeaderButton = new JButton("Add");
        JButton editCustomHeaderButton = new JButton("Edit");
        JButton removeCustomHeaderButton = new JButton("Remove");
        customHeadersButtonPanel.add(addCustomHeaderButton);
        //customHeadersButtonPanel.add(editCustomHeaderButton); // edit in-place in table
        customHeadersButtonPanel.add(removeCustomHeaderButton);

        String[] headersColumnNames = { "Name", "Value" };
        customHeadersTable = new JTable(new DefaultTableModel(headersColumnNames, 0));
        JScrollPane headersScrollPane = new JScrollPane(customHeadersTable);
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
        GridBagConstraints c4 = new GridBagConstraints();
        c4.gridy = 3;
        c4.anchor = GridBagConstraints.FIRST_LINE_START;

        outerPanel.add(globalSettingsPanel, c1);
        outerPanel.add(statusPanel, c2);
        outerPanel.add(profilePanel, c3);
        outerPanel.add(customHeadersPanel, c4);

        outerOuterPanel = new JPanel();
        outerOuterPanel.add(outerPanel);

        outerFrame = new JFrame();
        this.callbacks.customizeUiComponent(outerFrame);
        outerFrame.add(outerOuterPanel);

        // profile button handlers
        addProfileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                JDialog dialog = AWSProfileEditor.getAddProfileDialog(BurpExtender.this, null);
                callbacks.customizeUiComponent(dialog);
                dialog.setVisible(true);
            }
        });
        editProfileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                int[] rowIndeces = profileTable.getSelectedRows();
                if (rowIndeces.length == 1) {
                    DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
                    final String name = (String)model.getValueAt(rowIndeces[0], 0);
                    JDialog dialog = AWSProfileEditor.getAddProfileDialog(BurpExtender.this, profileNameMap.get(name));
                    callbacks.customizeUiComponent(dialog);
                    dialog.setVisible(true);
                }
                else {
                    updateStatus("Select a single profile to edit");
                }
            }
        });
        removeProfileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
                ArrayList<String> profileNames = new ArrayList<>();
                for (int rowIndex : profileTable.getSelectedRows()) {
                    profileNames.add((String)model.getValueAt(rowIndex, 0));
                }
                for (final String name : profileNames) {
                    deleteProfile(profileNameMap.get(name));
                }
            }
        });
        makeDefaultButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                int[] rowIndeces = profileTable.getSelectedRows();
                DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
                if (rowIndeces.length == 1) {
                    final String name = (String)model.getValueAt(rowIndeces[0], 0);
                    setDefaultProfileName(name);
                }
                else {
                    updateStatus("Select a single profile to make it default");
                }
            }
        });
        importProfileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                importProfiles();
            }
        });

        // custom header button handlers
        addCustomHeaderButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                DefaultTableModel model = (DefaultTableModel) customHeadersTable.getModel();
                model.addRow(new Object[]{"", ""});
            }
        });
        removeCustomHeaderButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                DefaultTableModel model = (DefaultTableModel) customHeadersTable.getModel();
                int[] rowIndeces = customHeadersTable.getSelectedRows();
                Arrays.sort(rowIndeces);
                for (int i = rowIndeces.length-1; i >= 0; i--) {
                    model.removeRow(rowIndeces[i]);
                }
            }
        });

        // log level combo box
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

        return outerFrame;
    }

    private boolean isSigningEnabled()
    {
        return this.signingEnabledCheckBox.isSelected();
    }


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
                buildUiTab();
                callbacks.addSuiteTab(BurpExtender.this);
                callbacks.registerHttpListener(BurpExtender.this);

                contextMenu = new AWSContextMenu(BurpExtender.this);
                callbacks.registerContextMenuFactory(contextMenu);
                callbacks.registerMessageEditorTabFactory(BurpExtender.this);

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
        this.callbacks.saveExtensionSetting(SETTING_EXTENSION_ENABLED, this.signingEnabledCheckBox.isSelected() ? "true" : "false");
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
            this.signingEnabledCheckBox.setSelected(true);
        }
        setDefaultProfileName(this.callbacks.loadExtensionSetting(SETTING_DEFAULT_PROFILE_NAME));
        final String customHeaderText = this.callbacks.loadExtensionSetting(SETTING_CUSTOM_HEADERS);
        if (customHeaderText != null) {
            setCustomHeadersInUI(customHeaderText);
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

    @Override
    public String getTabCaption()
    {
        return "SigV4";
    }

    @Override
    public Component getUiComponent() {
        return outerOuterPanel;
    }

    public List<JMenuItem> getContextMenuItems() {
        JMenu menu = new JMenu("AWSig");

        // add disable item
        JRadioButtonMenuItem item = new JRadioButtonMenuItem("Disable AWSig", !isSigningEnabled());
        item.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                signingEnabledCheckBox.setSelected(false);
            }
        });
        menu.add(item);

        ArrayList<String> profileList = new ArrayList<>(this.profileNameMap.keySet());
        profileList.add(0, NO_DEFAULT_PROFILE); // no default option

        for (final String name : profileList) {
            item = new JRadioButtonMenuItem(name, isSigningEnabled() && name.equals(getDefaultProfileName()));
            item.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    JRadioButtonMenuItem item = (JRadioButtonMenuItem)actionEvent.getSource();
                    setDefaultProfileName(item.getText());
                    signingEnabledCheckBox.setSelected(true);
                }
            });
            menu.add(item);
        }

        ArrayList<JMenuItem> list = new ArrayList<>();
        list.add(menu);
        return list;
    }

    // display status message in UI
    private void updateStatus(final String status)
    {
        logger.debug("Set Status: "+status);
        this.statusLabel.setText(status);
    }

    /*
    call this when profile list changes
    */
    private void updateAwsProfiles()
    {
        DefaultTableModel model = (DefaultTableModel)this.profileTable.getModel();
        model.setRowCount(0); // clear table
        final String defaultProfileName = (String)defaultProfileComboBox.getSelectedItem();
        defaultProfileComboBox.removeAllItems();
        defaultProfileComboBox.addItem(NO_DEFAULT_PROFILE);

        for (final String name : this.profileNameMap.keySet()) {
            AWSProfile profile = this.profileNameMap.get(name);
            model.addRow(new Object[] {profile.name, profile.accessKeyId, profile.secretKey, profile.region, profile.service});
            defaultProfileComboBox.addItem(name);
        }
        setDefaultProfileName(defaultProfileName);
    }


    public boolean addProfile(AWSProfile profile)
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
            updateAwsProfiles();
            if (p1 == null) {
                updateStatus("Added profile: " + profile.name);
            }
            else {
                updateStatus("Saved profile: " + profile.name);
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
        updateAwsProfiles();
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
            defaultProfileName = NO_DEFAULT_PROFILE;
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
        DefaultTableModel model = (DefaultTableModel) customHeadersTable.getModel();
        for (int i = 0; i < model.getRowCount(); i++) {
            final String name = (String)model.getValueAt(i, 0);
            final String value = (String)model.getValueAt(i, 1);
            if (!name.equals("")) { // skip empty header names
                headers.add(String.format("%s: %s", name, value));
            }
        }
        return headers;
    }

    private void setCustomHeadersInUI(final String customHeaderText)
    {
        DefaultTableModel model = (DefaultTableModel) customHeadersTable.getModel();
        for (final String header : customHeaderText.split("\n")) {
            final String[] tokens = header.split("[\\s:]+");
            if (tokens.length == 1) {
                model.addRow(new Object[]{tokens[0], ""});
            }
            else {
                model.addRow(new Object[]{tokens[0], tokens[1]});
            }
        }
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
        if (messageIsRequest && signingEnabledCheckBox.isSelected()) {
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

                byte[] requestBytes = signedRequest.getSignedRequestBytes(profile.secretKey);
                if (requestBytes != null) {
                    logger.info("Signed request with profile: "+profile);
                    messageInfo.setRequest(requestBytes);
                }
            }
        }
    }

}