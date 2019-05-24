package burp;

import javax.swing.*;
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
    private static final String SETTING_CUSTOM_HEADERS = "CustomSignedHeaders";
    private static final String SETTING_ADDITIONAL_SIGNED_HEADER_NAMES = "AdditionalSignedHeaderNames";
    private static final String SETTING_IN_SCOPE_ONLY = "InScopeOnly";

    private static final String NO_DEFAULT_PROFILE = "";

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private HashMap<String, AWSProfile> profileKeyIdMap; // map accessKeyId to profile
    private HashMap<String, AWSProfile> profileNameMap; // map accessKeyId to profile
    protected LogWriter logger;
    private AWSContextMenu contextMenu;

    private JLabel statusLabel;
    private JCheckBox signingEnabledCheckBox;
    private JComboBox defaultProfileComboBox;
    private JComboBox logLevelComboBox;
    private JCheckBox persistProfilesCheckBox;
    private JCheckBox inScopeOnlyCheckBox;
    private JTextField additionalSignedHeadersField;

    private JTable profileTable;
    private JTable customHeadersTable;
    private JScrollPane outerScrollPane;

    // mimic burp colors
    protected static final Color textOrange = new Color(255, 102, 51);
    protected static final Color darkOrange = new Color(226, 73, 33);

    public BurpExtender()
    {
    }

    private void buildUiTab()
    {
        final Font sectionFont = new JLabel().getFont().deriveFont(Font.BOLD, 15);

        //
        // global settings, checkboxes
        //
        JPanel globalSettingsPanel = new JPanel();
        globalSettingsPanel.setLayout(new GridBagLayout());
        JLabel settingsLabel = new JLabel("Settings");
        settingsLabel.setForeground(this.textOrange);
        settingsLabel.setFont(sectionFont);
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
        JPanel otherSettingsPanel = new JPanel();
        defaultProfileComboBox = new JComboBox();
        logLevelComboBox = new JComboBox();
        otherSettingsPanel.add(new JLabel("Log Level"));
        otherSettingsPanel.add(logLevelComboBox);
        otherSettingsPanel.add(new JLabel("Default Profile"));
        otherSettingsPanel.add(defaultProfileComboBox);

        GridBagConstraints c00 = new GridBagConstraints(); c00.anchor = GridBagConstraints.FIRST_LINE_START; c00.gridy = 0; c00.gridwidth = 2;
        GridBagConstraints c01 = new GridBagConstraints(); c01.anchor = GridBagConstraints.FIRST_LINE_START; c01.gridy = 1; c01.gridwidth = 2; c01.insets = new Insets(10, 0, 10, 0);
        GridBagConstraints c02 = new GridBagConstraints(); c02.anchor = GridBagConstraints.FIRST_LINE_START; c02.gridy = 2;
        GridBagConstraints c03 = new GridBagConstraints(); c03.anchor = GridBagConstraints.FIRST_LINE_START; c03.gridy = 3;

        globalSettingsPanel.add(settingsLabel, c00);
        globalSettingsPanel.add(new JLabel("<html>Change plugin behavior. Set <i>Default Profile</i> to force certain credentials to be used to sign requests."), c01);
        globalSettingsPanel.add(checkBoxPanel, c02);
        globalSettingsPanel.add(otherSettingsPanel, c03);

        //
        // status label
        //
        JPanel statusPanel = new JPanel();
        statusLabel = new JLabel();
        statusPanel.add(statusLabel);

        //
        // profiles table
        //
        JPanel profilePanel = new JPanel(new GridBagLayout());
        JLabel profileLabel = new JLabel("AWS Credentials");
        profileLabel.setForeground(this.textOrange);
        profileLabel.setFont(sectionFont);

        JButton addProfileButton = new JButton("Add");
        JButton editProfileButton = new JButton("Edit");
        JButton removeProfileButton = new JButton("Remove");
        JButton makeDefaultButton = new JButton("Default");
        JButton importProfileButton = new JButton("Import");
        JPanel profileButtonPanel = new JPanel(new GridLayout(5, 1));
        profileButtonPanel.add(addProfileButton);
        profileButtonPanel.add(editProfileButton);
        profileButtonPanel.add(removeProfileButton);
        profileButtonPanel.add(makeDefaultButton);
        profileButtonPanel.add(importProfileButton);

        final String[] profileColumnNames = {"Name", "KeyId", "SecretKey", "Region", "Service"};
        profileTable = new JTable(new DefaultTableModel(profileColumnNames, 0)
        {
            @Override
            public boolean isCellEditable(int row, int column)
            {
                // prevent table cells from being edited. must use dialog to edit.
                return false;
            }
        });

        JScrollPane profileScrollPane = new JScrollPane(profileTable);
        profileScrollPane.setPreferredSize(new Dimension(1000, 200));
        GridBagConstraints c000 = new GridBagConstraints(); c000.gridy = 0; c000.gridwidth = 2; c000.anchor = GridBagConstraints.FIRST_LINE_START;
        GridBagConstraints c001 = new GridBagConstraints(); c001.gridy = 1; c001.gridwidth = 2; c001.anchor = GridBagConstraints.FIRST_LINE_START; c001.insets = new Insets(10, 0, 10, 0);
        GridBagConstraints c002 = new GridBagConstraints(); c002.gridy = 2; c002.gridx = 0; c002.anchor = GridBagConstraints.FIRST_LINE_START;
        GridBagConstraints c003 = new GridBagConstraints(); c003.gridy = 2; c003.gridx = 1; c003.anchor = GridBagConstraints.FIRST_LINE_START;
        profilePanel.add(profileLabel, c000);
        profilePanel.add(new JLabel("<html>Add AWS credentials using your <i>aws_access_key_id</i> and <i>aws_secret_access_key</i>.</html>"), c001);
        profilePanel.add(profileButtonPanel, c002);
        profilePanel.add(profileScrollPane, c003);

        //
        // custom signed headers table
        //
        JPanel customHeadersPanel = new JPanel(new GridBagLayout());
        JLabel customHeadersLabel = new JLabel("Custom Signed Headers");
        customHeadersLabel.setForeground(this.textOrange);
        customHeadersLabel.setFont(sectionFont);
        JPanel customHeadersButtonPanel = new JPanel();
        customHeadersButtonPanel.setLayout(new GridLayout(3, 1));
        JButton addCustomHeaderButton = new JButton("Add");
        //JButton editCustomHeaderButton = new JButton("Edit");
        JButton removeCustomHeaderButton = new JButton("Remove");
        customHeadersButtonPanel.add(addCustomHeaderButton);
        //customHeadersButtonPanel.add(editCustomHeaderButton); // edit in-place in table
        customHeadersButtonPanel.add(removeCustomHeaderButton);

        final String[] headersColumnNames = {"Name", "Value"};
        customHeadersTable = new JTable(new DefaultTableModel(headersColumnNames, 0));
        JScrollPane headersScrollPane = new JScrollPane(customHeadersTable);
        headersScrollPane.setPreferredSize(new Dimension(1000, 200));

        GridBagConstraints c100 = new GridBagConstraints(); c100.gridy = 0; c100.gridwidth = 2; c100.anchor = GridBagConstraints.FIRST_LINE_START;
        GridBagConstraints c101 = new GridBagConstraints(); c101.gridy = 1; c101.gridwidth = 2; c101.anchor = GridBagConstraints.FIRST_LINE_START; c101.insets = new Insets(10, 0, 10, 0);
        GridBagConstraints c102 = new GridBagConstraints(); c102.gridy = 2; c102.gridx = 0; c102.anchor = GridBagConstraints.FIRST_LINE_START;
        GridBagConstraints c103 = new GridBagConstraints(); c103.gridy = 2; c103.gridx = 1; c103.anchor = GridBagConstraints.FIRST_LINE_START;
        customHeadersPanel.add(customHeadersLabel, c100);
        customHeadersPanel.add(new JLabel("Add request headers to be included in the signature. These can be edited in place."), c101);
        customHeadersPanel.add(customHeadersButtonPanel, c102);
        customHeadersPanel.add(headersScrollPane, c103);

        //
        // additional headers to sign
        //
        JPanel additionalSignedHeadersPanel = new JPanel(new GridBagLayout());
        JLabel additionalHeadersLabel = new JLabel("Signed Headers");
        additionalHeadersLabel.setForeground(this.textOrange);
        additionalHeadersLabel.setFont(sectionFont);
        additionalSignedHeadersField = new JTextField("", 65);
        GridBagConstraints c200 = new GridBagConstraints(); c200.gridy = 0; c200.gridwidth = 2; c200.anchor = GridBagConstraints.FIRST_LINE_START;
        GridBagConstraints c201 = new GridBagConstraints(); c201.gridy = 1; c201.gridwidth = 2; c201.anchor = GridBagConstraints.FIRST_LINE_START; c201.insets = new Insets(10, 0, 10, 0);
        GridBagConstraints c202 = new GridBagConstraints(); c202.gridy = 2; c202.anchor = GridBagConstraints.FIRST_LINE_START;
        additionalSignedHeadersPanel.add(additionalHeadersLabel, c200);
        additionalSignedHeadersPanel.add(new JLabel("Specify comma-separated headers in the original request to include in the signature."), c201);
        additionalSignedHeadersPanel.add(additionalSignedHeadersField, c202);

        //
        // put it all together
        //
        List<GridBagConstraints> sectionConstraints = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            GridBagConstraints c = new GridBagConstraints();
            c.gridy = i;
            c.gridx = 0;
            // add padding in all directions
            c.insets = new Insets(10, 10, 10, 10);
            c.anchor = GridBagConstraints.FIRST_LINE_START;
            c.weightx = 1.0;
            sectionConstraints.add(c);
        }

        JPanel outerPanel = new JPanel(new GridBagLayout());
        outerPanel.add(globalSettingsPanel, sectionConstraints.remove(0));
        GridBagConstraints c = sectionConstraints.remove(0);
        c.fill = GridBagConstraints.HORIZONTAL; // have separator span entire width of display
        outerPanel.add(new JSeparator(SwingConstants.HORIZONTAL), c);
        ////outerPanel.add(statusPanel, sectionConstraints.remove(0));
        outerPanel.add(profilePanel, sectionConstraints.remove(0));
        c = sectionConstraints.remove(0);
        c.fill = GridBagConstraints.HORIZONTAL;
        outerPanel.add(new JSeparator(SwingConstants.HORIZONTAL), c);
        outerPanel.add(customHeadersPanel, sectionConstraints.remove(0));
        c = sectionConstraints.remove(0);
        c.fill = GridBagConstraints.HORIZONTAL;
        outerPanel.add(new JSeparator(SwingConstants.HORIZONTAL), c);
        outerPanel.add(additionalSignedHeadersPanel, sectionConstraints.remove(0));

        // use outerOuterPanel to force components north
        JPanel outerOuterPanel = new JPanel(new BorderLayout());
        outerOuterPanel.add(outerPanel, BorderLayout.PAGE_START);
        outerScrollPane = new JScrollPane(outerOuterPanel);
        outerScrollPane.getVerticalScrollBar().setUnitIncrement(18);

        this.callbacks.customizeUiComponent(outerPanel);

        // profile button handlers
        addProfileButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                JDialog dialog = new AWSProfileEditorDialog(null, "Add Profile", true, null, BurpExtender.this);
                callbacks.customizeUiComponent(dialog);
                dialog.setVisible(true);
            }
        });
        editProfileButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                int[] rowIndeces = profileTable.getSelectedRows();
                if (rowIndeces.length == 1) {
                    DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
                    final String name = (String) model.getValueAt(rowIndeces[0], 0);
                    JDialog dialog = new AWSProfileEditorDialog(null, "Edit Profile", true, profileNameMap.get(name), BurpExtender.this);
                    callbacks.customizeUiComponent(dialog);
                    dialog.setVisible(true);
                }
                else {
                    updateStatus("Select a single profile to edit");
                }
            }
        });
        removeProfileButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
                ArrayList<String> profileNames = new ArrayList<>();
                for (int rowIndex : profileTable.getSelectedRows()) {
                    profileNames.add((String) model.getValueAt(rowIndex, 0));
                }
                for (final String name : profileNames) {
                    deleteProfile(profileNameMap.get(name));
                }
            }
        });
        makeDefaultButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                int[] rowIndeces = profileTable.getSelectedRows();
                DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
                if (rowIndeces.length == 1) {
                    final String name = (String) model.getValueAt(rowIndeces[0], 0);
                    setDefaultProfileName(name);
                }
                else {
                    updateStatus("Select a single profile to make it default");
                }
            }
        });
        importProfileButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                try {
                    AWSProfileImportDialog importDialog = new AWSProfileImportDialog(null, "Import Profiles", true, BurpExtender.this);
                    callbacks.customizeUiComponent(importDialog);
                    importDialog.setVisible(true);
                }
                catch (Exception exc) {
                    logger.error("Failed to display import dialog: "+exc);
                }
            }
        });

        // custom header button handlers
        addCustomHeaderButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                DefaultTableModel model = (DefaultTableModel) customHeadersTable.getModel();
                model.addRow(new Object[]{"", ""});
            }
        });
        removeCustomHeaderButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                DefaultTableModel model = (DefaultTableModel) customHeadersTable.getModel();
                int[] rowIndeces = customHeadersTable.getSelectedRows();
                Arrays.sort(rowIndeces);
                for (int i = rowIndeces.length - 1; i >= 0; i--) {
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
            public String toString()
            {
                return this.levelName;
            }
        }
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.DEBUG_LEVEL));
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.INFO_LEVEL));
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.ERROR_LEVEL));
        this.logLevelComboBox.addItem(new LogLevelComboBoxItem(LogWriter.FATAL_LEVEL));
        this.logLevelComboBox.setSelectedIndex(logger.getLevel());

        this.logLevelComboBox.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                logger.setLevel(((LogLevelComboBoxItem) logLevelComboBox.getSelectedItem()).logLevel);
            }
        });
    }

    private boolean isSigningEnabled()
    {
        return this.signingEnabledCheckBox.isSelected();
    }


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
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

        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
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
        this.callbacks.saveExtensionSetting(SETTING_ADDITIONAL_SIGNED_HEADER_NAMES, String.join(",", getAdditionalSignedHeadersFromUI()));
        this.callbacks.saveExtensionSetting(SETTING_IN_SCOPE_ONLY, this.inScopeOnlyCheckBox.isSelected() ? "true" : "false");
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

        setDefaultProfileName(this.callbacks.loadExtensionSetting(SETTING_DEFAULT_PROFILE_NAME));

        String setting = this.callbacks.loadExtensionSetting(SETTING_PERSISTENT_PROFILES);
        if ((setting != null) && setting.toLowerCase().equals("true")) {
            this.persistProfilesCheckBox.setSelected(true);
        }
        setting = this.callbacks.loadExtensionSetting(SETTING_EXTENSION_ENABLED);
        if ((setting == null) || setting.toLowerCase().equals("true")) {
            this.signingEnabledCheckBox.setSelected(true);
        }
        setting = this.callbacks.loadExtensionSetting(SETTING_CUSTOM_HEADERS);
        if (setting != null) {
            setCustomHeadersInUI(setting);
        }
        setting = this.callbacks.loadExtensionSetting(SETTING_ADDITIONAL_SIGNED_HEADER_NAMES);
        if (setting != null) {
            this.additionalSignedHeadersField.setText(setting);
        }

        setting = this.callbacks.loadExtensionSetting(SETTING_IN_SCOPE_ONLY);
        if ((setting != null) && setting.toLowerCase().equals("true")) {
            this.inScopeOnlyCheckBox.setSelected(true);
        }
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
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
    public Component getUiComponent()
    {
        return outerScrollPane;
    }

    public List<JMenuItem> getContextMenuItems()
    {
        JMenu menu = new JMenu("SigV4");

        // add disable item
        JRadioButtonMenuItem item = new JRadioButtonMenuItem("<html><i>Disabled</i></html>", !isSigningEnabled());
        item.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                signingEnabledCheckBox.setSelected(false);
            }
        });
        menu.add(item);

        ArrayList<String> profileList = new ArrayList<>(this.profileNameMap.keySet());
        profileList.add(0, NO_DEFAULT_PROFILE); // no default option

        for (final String name : profileList) {
            item = new JRadioButtonMenuItem(name, isSigningEnabled() && name.equals(getDefaultProfileName()));
            item.addActionListener(new ActionListener()
            {
                @Override
                public void actionPerformed(ActionEvent actionEvent)
                {
                    JRadioButtonMenuItem item = (JRadioButtonMenuItem) actionEvent.getSource();
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
        logger.debug("Set Status: " + status);
        this.statusLabel.setText(status);
    }

    /*
    call this when profile list changes
    */
    private void updateAwsProfiles()
    {
        DefaultTableModel model = (DefaultTableModel) this.profileTable.getModel();
        model.setRowCount(0); // clear table
        final String defaultProfileName = (String) defaultProfileComboBox.getSelectedItem();
        defaultProfileComboBox.removeAllItems();
        defaultProfileComboBox.addItem(NO_DEFAULT_PROFILE);

        // sort by name in table
        List<String> profileNames = new ArrayList<>(this.profileNameMap.keySet());
        Collections.sort(profileNames);

        for (final String name : profileNames) {
            AWSProfile profile = this.profileNameMap.get(name);
            model.addRow(new Object[]{profile.name, profile.accessKeyId, profile.secretKey, profile.region, profile.service});
            defaultProfileComboBox.addItem(name);
        }
        setDefaultProfileName(defaultProfileName);
    }


    protected boolean addProfile(AWSProfile profile)
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

    /*
    if newProfile is valid, delete oldProfile and add newProfile.
     */
    protected boolean updateProfile(final AWSProfile oldProfile, final AWSProfile newProfile)
    {
        if (oldProfile == null) {
            return addProfile(newProfile);
        }
        if (newProfile.name.length() > 0) {
            // remove any profile with same name
            AWSProfile p1 = this.profileNameMap.get(oldProfile.name);
            AWSProfile p2 = this.profileKeyIdMap.get(oldProfile.accessKeyId);
            if ((p1 == null) || (p2 == null)) {
                updateStatus("Update profile failed. Old profile doesn't exist.");
                return false;
            }
            deleteProfile(oldProfile);
            if (!addProfile(newProfile)) {
                addProfile(oldProfile);
                return false;
            }
            return true;
        }
        return false;
    }


    protected void deleteProfile(AWSProfile profile)
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
        Path credPath = Paths.get(System.getProperty("user.home"), ".aws", "credentials");
        if (!Files.exists(credPath)) {
            JFileChooser chooser = new JFileChooser(System.getProperty("user.home"));
            chooser.setFileHidingEnabled(false);
            if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                credPath = Paths.get(chooser.getSelectedFile().getPath());
            }
            else {
                return;
            }
        }
        logger.info("Importing AWS credentials from: " + credPath);

        int count = 0;
        for (AWSProfile profile : AWSProfile.fromCredentialPath(credPath)) {
            if (addProfile(profile)) {
                logger.info("Imported profile: " + profile);
                count += 1;
            }
        }

        // try to import creds from environment variables
        AWSProfile profile = AWSProfile.fromEnvironment();
        if (profile != null) {
            if (addProfile(profile)) {
                logger.info("Imported profile: " + profile);
                count += 1;
            }
        }
        updateStatus(String.format("Imported %d profiles", count));
    }

    /*
    Check if the request is for AWS. Can be POST or GET request.
    */
    public static boolean isAwsRequest(IRequestInfo request)
    {
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
            logger.debug("+" + header);
        }
    }

    private String getDefaultProfileName()
    {
        String defaultProfileName = (String) this.defaultProfileComboBox.getSelectedItem();
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

    private List<String> getAdditionalSignedHeadersFromUI()
    {
        return Arrays.asList(additionalSignedHeadersField.getText().split(",+"));
    }

    /* get the additional headers specified in the UI */
    private List<String> getCustomHeadersFromUI()
    {
        ArrayList<String> headers = new ArrayList<>();
        DefaultTableModel model = (DefaultTableModel) customHeadersTable.getModel();
        for (int i = 0; i < model.getRowCount(); i++) {
            final String name = (String) model.getValueAt(i, 0);
            final String value = (String) model.getValueAt(i, 1);
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

        // add names of additional headers to sign
        signedRequest.addSignedHeaderNames(getAdditionalSignedHeadersFromUI());

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
                logger.debug("Skipping out of scope request: " + request.getUrl());
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
                    logger.info("Signed request with profile: " + profile);
                    messageInfo.setRequest(requestBytes);
                }
            }
        }
    }

}