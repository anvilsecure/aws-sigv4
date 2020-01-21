package burp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.reflect.Type;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.*;
import java.util.stream.Collectors;


public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IExtensionStateListener, IMessageEditorTabFactory, IContextMenuFactory
{
    private static final String AWSIG_VERSION = "1.2.1";

    private static final String BURP_SETTINGS_KEY = "JsonSettings";
    private static final String SETTING_VERSION = "AwsigVersion";
    private static final String SETTING_PROFILES = "SerializedProfileList";
    private static final String SETTING_PERSISTENT_PROFILES = "PersistentProfiles";
    private static final String SETTING_EXTENSION_ENABLED = "ExtensionEnabled";
    private static final String SETTING_DEFAULT_PROFILE_NAME = "DefaultProfileName";
    private static final String SETTING_LOG_LEVEL = "LogLevel";
    private static final String SETTING_CUSTOM_HEADERS = "CustomSignedHeaders";
    private static final String SETTING_CUSTOM_HEADERS_OVERWRITE = "CustomSignedHeadersOverwrite";
    private static final String SETTING_ADDITIONAL_SIGNED_HEADER_NAMES = "AdditionalSignedHeaderNames";
    private static final String SETTING_IN_SCOPE_ONLY = "InScopeOnly";

    private static final String AWS_STS_HOSTNAME = "sts.amazonaws.com";
    private static final String AWS_STS_REGION = "us-east-1";
    private static final String AWS_STS_SIGNAME = "sts";

    private static final String NO_DEFAULT_PROFILE = "";

    protected IExtensionHelpers helpers;
    protected IBurpExtenderCallbacks callbacks;
    //TODO remove requirement for profiles to have a keyId
    private HashMap<String, AWSProfile> profileKeyIdMap; // map accessKeyId to profile
    private HashMap<String, AWSProfile> profileNameMap; // map name to profile
    protected LogWriter logger = LogWriter.getLogger();

    private JLabel statusLabel;
    private JCheckBox signingEnabledCheckBox;
    private JComboBox defaultProfileComboBox;
    private JComboBox logLevelComboBox;
    private JCheckBox persistProfilesCheckBox;
    private JCheckBox inScopeOnlyCheckBox;
    private JTextField additionalSignedHeadersField;

    private JTable profileTable;
    private JTable customHeadersTable;
    private JCheckBox customHeadersOverwriteCheckbox;
    private JScrollPane outerScrollPane;

    // mimic burp colors
    protected static final Color textOrange = new Color(255, 102, 51);
    protected static final Color darkOrange = new Color(226, 73, 33);

    private static BurpExtender burpInstance;

    public static BurpExtender getBurp()
    {
        return burpInstance;
    }

    public BurpExtender() {}

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
        globalSettingsPanel.add(new JLabel("<html>Change plugin behavior. Set <i>Default Profile</i> to force signing of all requests with the specified profile credentials."), c01);
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
        JButton testProfileButton = new JButton("Test");
        JButton importProfileButton = new JButton("Import");
        JButton exportProfileButton = new JButton("Export");
        JPanel profileButtonPanel = new JPanel(new GridLayout(7, 1));
        profileButtonPanel.add(addProfileButton);
        profileButtonPanel.add(editProfileButton);
        profileButtonPanel.add(removeProfileButton);
        profileButtonPanel.add(testProfileButton);
        profileButtonPanel.add(importProfileButton);
        profileButtonPanel.add(exportProfileButton);

        final String[] profileColumnNames = {"Name", "KeyId", "Credential Provider", "Region", "Service"};
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
        customHeadersOverwriteCheckbox = new JCheckBox("Overwrite existing headers");
        customHeadersOverwriteCheckbox.setToolTipText("Default behavior is to append these headers even if they exist in original request");
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
        headersScrollPane.setPreferredSize(new Dimension(1000, 150));

        GridBagConstraints c100 = new GridBagConstraints(); c100.gridy = 0; c100.gridwidth = 2; c100.anchor = GridBagConstraints.FIRST_LINE_START;
        GridBagConstraints c101 = new GridBagConstraints(); c101.gridy = 1; c101.gridwidth = 2; c101.anchor = GridBagConstraints.FIRST_LINE_START; c101.insets = new Insets(10, 0, 10, 0);
        GridBagConstraints c102 = new GridBagConstraints(); c102.gridy = 2; c102.gridx = 1; c102.anchor = GridBagConstraints.FIRST_LINE_START;
        GridBagConstraints c103 = new GridBagConstraints(); c103.gridy = 3; c103.gridx = 0; c103.anchor = GridBagConstraints.FIRST_LINE_START;
        GridBagConstraints c104 = new GridBagConstraints(); c104.gridy = 3; c104.gridx = 1; c104.anchor = GridBagConstraints.FIRST_LINE_START;
        customHeadersPanel.add(customHeadersLabel, c100);
        customHeadersPanel.add(new JLabel("Add request headers to be included in the signature. These can be edited in place."), c101);
        customHeadersPanel.add(customHeadersOverwriteCheckbox, c102);
        customHeadersPanel.add(customHeadersButtonPanel, c103);
        customHeadersPanel.add(headersScrollPane, c104);

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
        //outerPanel.add(statusPanel, sectionConstraints.remove(0));
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
        testProfileButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                // build a signed request to STS GetCallerIdentity API to test the credentials and send it to repeater
                // Notes
                //   * this request will be subject to any modifications specified in the plugin
                //   * if profile has a region set, it will override the region set here
                //     - temp fix is to check "In-scope Only" and ensure AWS_STS_HOSTNAME is not in scope
                //   * this inserts a header to force the use of the specified profile so it isn't overridden by the default profile
                int[] rowIndeces = profileTable.getSelectedRows();
                DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
                if (rowIndeces.length == 1) {
                    final String name = (String) model.getValueAt(rowIndeces[0], 0);
                    AWSProfile profile = profileNameMap.get(name);
                    // build the request
                    final String requestBody = "Version=2011-06-15&Action=GetCallerIdentity";
                    List<String> headers = new ArrayList<>();
                    headers.add("POST / HTTP/1.1");
                    headers.add("Host: "+AWS_STS_HOSTNAME);
                    headers.add("Content-Type: application/x-www-form-urlencoded; charset=utf-8");
                    IHttpService httpService = helpers.buildHttpService(AWS_STS_HOSTNAME, 443, true);
                    AWSSignedRequest signedRequest = new AWSSignedRequest(
                            httpService,
                            helpers.buildHttpMessage(headers, helpers.stringToBytes(requestBody)),
                            BurpExtender.this);
                    signedRequest.applyProfile(profile);
                    signedRequest.setRegion(AWS_STS_REGION);
                    signedRequest.setService(AWS_STS_SIGNAME);

                    // Rebuild signed request bytes with the profile header. this is required since this header gets stripped
                    // after the request is signed. this header will ensure the message is signed with the correct profile
                    final byte[] signedRequestBytes = signedRequest.getSignedRequestBytes(profile.getCredential());
                    headers = helpers.analyzeRequest(signedRequestBytes).getHeaders();
                    headers.add(String.format("%s: %s", AWSSignedRequest.PROFILE_HEADER_NAME, profile.getName()));

                    callbacks.sendToRepeater(httpService.getHost(),
                            httpService.getPort(),
                            true /* useHttps */,
                            helpers.buildHttpMessage(headers, signedRequest.getPayloadBytes()),
                            profile.getName());
                }
                else {
                    updateStatus("Select a single profile to test");
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
        exportProfileButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                JFileChooser chooser = new JFileChooser(System.getProperty("user.home"));
                chooser.setFileHidingEnabled(false);
                if (chooser.showOpenDialog(getUiComponent()) == JFileChooser.APPROVE_OPTION) {
                    final Path exportPath = Paths.get(chooser.getSelectedFile().getPath());
                    ArrayList<AWSProfile> awsProfiles = new ArrayList<>();
                    for (final String name : profileNameMap.keySet()) {
                        awsProfiles.add(profileNameMap.get(name));
                    }
                    int exportCount = AWSProfile.exportToFilePath(awsProfiles, exportPath);
                    final String msg = String.format("Exported %d profiles to %s", exportCount, exportPath);
                    JOptionPane.showMessageDialog(getUiComponent(), msg);
                    logger.info(msg);
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

    public boolean isSigningEnabled()
    {
        return this.signingEnabledCheckBox.isSelected();
    }
    public boolean isInScopeOnlyEnabled() { return this.inScopeOnlyCheckBox.isSelected(); }


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        burpInstance = this;

        this.helpers = callbacks.getHelpers();
        this.callbacks = callbacks;

        callbacks.setExtensionName("SigV4");
        callbacks.registerExtensionStateListener(this);

        this.logger.configure(callbacks.getStdout(), callbacks.getStderr(), LogWriter.DEFAULT_LEVEL);
        final String setting = this.callbacks.loadExtensionSetting(SETTING_LOG_LEVEL);
        if (setting != null) {
            this.logger.setLevel(Integer.parseInt(setting));
        }

        this.profileKeyIdMap = new HashMap<>();
        this.profileNameMap = new HashMap<>();

        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                buildUiTab();
                loadExtensionSettings();
                callbacks.addSuiteTab(BurpExtender.this);
                callbacks.registerHttpListener(BurpExtender.this);
                callbacks.registerContextMenuFactory(BurpExtender.this);
                callbacks.registerMessageEditorTabFactory(BurpExtender.this);
                logger.info("Loaded AWSig "+AWSIG_VERSION);
            }
        });
    }

    private void saveExtensionSettings()
    {
        this.callbacks.saveExtensionSetting(SETTING_LOG_LEVEL, Integer.toString(this.logger.getLevel()));
        this.callbacks.saveExtensionSetting(SETTING_VERSION, AWSIG_VERSION);

        HashMap<String, Object> settings = new HashMap<>();
        settings.put(SETTING_PERSISTENT_PROFILES, this.persistProfilesCheckBox.isSelected());
        settings.put(SETTING_EXTENSION_ENABLED, this.signingEnabledCheckBox.isSelected());
        settings.put(SETTING_DEFAULT_PROFILE_NAME, this.getDefaultProfileName());
        settings.put(SETTING_CUSTOM_HEADERS, getCustomHeadersFromUI());
        settings.put(SETTING_CUSTOM_HEADERS_OVERWRITE, this.customHeadersOverwriteCheckbox.isSelected());
        settings.put(SETTING_ADDITIONAL_SIGNED_HEADER_NAMES, getAdditionalSignedHeadersFromUI());
        settings.put(SETTING_IN_SCOPE_ONLY, this.inScopeOnlyCheckBox.isSelected());
        this.callbacks.saveExtensionSetting(BURP_SETTINGS_KEY, new Gson().toJson(settings));

        if (this.persistProfilesCheckBox.isSelected()) {
            Gson gson = new GsonBuilder()
                    .setPrettyPrinting()
                    .registerTypeAdapter(AWSCredential.class, new AWSCredentialSerializer())
                    .registerTypeAdapter(AWSCredentialProvider.class, new AWSCredentialProviderSerializer())
                    .create();
            this.callbacks.saveExtensionSetting(SETTING_PROFILES, gson.toJson(this.profileNameMap));
            logger.info(String.format("Saved %d profile(s)", this.profileNameMap.size()));
        }
        else {
            this.callbacks.saveExtensionSetting(SETTING_PROFILES, "{}");
        }

    }

    private void loadExtensionSettings()
    {
        // plugin version that added the settings. in the future use this to migrate settings.
        final String pluginVersion = this.callbacks.loadExtensionSetting(SETTING_VERSION);
        if (pluginVersion != null)
            logger.info("Found settings for version "+pluginVersion);
        else
            logger.info("Found settings for version < 1.2.0");

        final String jsonSettingsString = this.callbacks.loadExtensionSetting(BURP_SETTINGS_KEY);
        if (jsonSettingsString == null || jsonSettingsString.equals("")) {
            logger.info("No plugin settings found");
        }
        else {
            JsonObject settings = new Gson().fromJson(jsonSettingsString, JsonObject.class);
            if (settings.has(SETTING_DEFAULT_PROFILE_NAME))
                setDefaultProfileName(settings.get(SETTING_DEFAULT_PROFILE_NAME).getAsString());
            else
                setDefaultProfileName(null);
            if (settings.has(SETTING_DEFAULT_PROFILE_NAME))
                this.persistProfilesCheckBox.setSelected(settings.get(SETTING_PERSISTENT_PROFILES).getAsBoolean());
            else
                this.persistProfilesCheckBox.setSelected(false);
            if (settings.has(SETTING_EXTENSION_ENABLED))
                this.signingEnabledCheckBox.setSelected(settings.get(SETTING_EXTENSION_ENABLED).getAsBoolean());
            else
                 this.signingEnabledCheckBox.setSelected(true);

            if (settings.has(SETTING_CUSTOM_HEADERS)) {
                List<String> customHeaders = new ArrayList<>();
                for (final JsonElement header : settings.get(SETTING_CUSTOM_HEADERS).getAsJsonArray()) {
                    customHeaders.add(header.getAsString());
                }
                setCustomHeadersInUI(customHeaders);
            }

            if (settings.has(SETTING_CUSTOM_HEADERS_OVERWRITE))
                this.customHeadersOverwriteCheckbox.setSelected(settings.get(SETTING_CUSTOM_HEADERS_OVERWRITE).getAsBoolean());
            else
                this.customHeadersOverwriteCheckbox.setSelected(false);
            if (settings.has(SETTING_ADDITIONAL_SIGNED_HEADER_NAMES)) {
                List<String> additionalHeaders = new ArrayList<>();
                for (JsonElement header : settings.get(SETTING_ADDITIONAL_SIGNED_HEADER_NAMES).getAsJsonArray()) {
                    additionalHeaders.add(header.getAsString());
                }
                this.additionalSignedHeadersField.setText(String.join(", ", additionalHeaders));
            }
            if (settings.has(SETTING_IN_SCOPE_ONLY))
                this.inScopeOnlyCheckBox.setSelected(settings.get(SETTING_IN_SCOPE_ONLY).getAsBoolean());
            else
                this.inScopeOnlyCheckBox.setSelected(false);
        }

        //TODO catch exceptions and overwrite invalid settings
        final String profilesJsonString = this.callbacks.loadExtensionSetting(SETTING_PROFILES);
        if (profilesJsonString != null && !profilesJsonString.equals("")) {
            Gson gson = new GsonBuilder()
                    .registerTypeAdapter(AWSCredential.class, new AWSCredentialSerializer())
                    .registerTypeAdapter(AWSCredentialProvider.class, new AWSCredentialProviderSerializer())
                    .create();
            final Type hashMapType = new TypeToken<HashMap<String, AWSProfile>>(){}.getType();
            Map<String, AWSProfile> profileMap = gson.fromJson(profilesJsonString, hashMapType);
            for (final String name : profileMap.keySet()) {
                addProfile(profileMap.get(name));
            }
        }

    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        return new AWSMessageEditorTab(controller, editable, this);
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

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)
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

        // insert "auto" profile option
        List<String> profileList = getSortedProfileNames();
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

        // add menu item to copy signed url to clipboard. this menu option is only available for GET requests.
        // TODO: add subitems to get signed url with any profile?
        switch (invocation.getInvocationContext()) {
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            case IContextMenuInvocation.CONTEXT_PROXY_HISTORY:
                IHttpRequestResponse[] messages = invocation.getSelectedMessages();
                IRequestInfo requestInfo = helpers.analyzeRequest(messages[0]);
                boolean isSigV4 = isAwsRequest(requestInfo);
                if ((messages.length > 0) && requestInfo.getMethod().toUpperCase().equals("GET") && isSigV4) {
                    JMenuItem signedUrlItem = new JMenuItem("Copy Signed URL");
                    signedUrlItem.addActionListener(new ActionListener()
                    {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent)
                        {
                            AWSSignedRequest signedRequest = new AWSSignedRequest(messages[0], BurpExtender.this);
                            final AWSProfile profile = customizeSignedRequest(signedRequest);
                            String signedUrl = ""; // clear clipboard on error
                            if (profile == null) {
                                logger.error("Failed to apply custom settings to signed request");
                            }
                            else {
                                // sign a url valid for 120 seconds. XXX consider making this configurable.
                                signedUrl = signedRequest.getSignedUrl(profile.getCredential(), 120);
                            }
                            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                            clipboard.setContents(new StringSelection(signedUrl), null);
                        }
                    });
                    list.add(signedUrlItem);
                }
                if ((messages.length > 0) && (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) && !isSigV4) {
                    JMenu addSignatureMenu = new JMenu("Add Signature");
                    for (final String name : profileList) {
                        if (name.length() == 0) continue;
                        JMenuItem sigItem = new JMenuItem(name);
                        sigItem.addActionListener(new ActionListener()
                        {
                            @Override
                            public void actionPerformed(ActionEvent actionEvent)
                            {
                                JMenuItem sigItem = (JMenuItem)actionEvent.getSource();
                                AWSSignedRequest signedRequest = AWSSignedRequest.fromUnsignedRequest(messages[0], profileNameMap.get(sigItem.getText()), BurpExtender.this);
                                final AWSProfile profile = customizeSignedRequest(signedRequest);
                                if (profile == null) {
                                    // XXX maybe use an "Add Profile" dialog here?
                                    logger.error("Invalid profile specified. KeyId does not exist: "+signedRequest.getAccessKeyId());
                                    return;
                                }
                                // if region or service is missing, prompt user. do not re-prompt if values are left blank
                                if (signedRequest.getService().equals("") || signedRequest.getRegion().equals("")) {
                                    AWSProfileEditorReadOnlyDialog dialog = new AWSProfileEditorReadOnlyDialog(null, "Add Signature", true, profile, BurpExtender.this);
                                    callbacks.customizeUiComponent(dialog);
                                    dialog.disableForEdit();
                                    // set focus to first missing field
                                    if (signedRequest.getRegion().equals("")) {
                                        dialog.regionTextField.requestFocus();
                                    }
                                    else {
                                        dialog.serviceTextField.requestFocus();
                                    }
                                    dialog.setVisible(true);
                                    if (dialog.getProfile() == null) {
                                        // user hit "Cancel", abort.
                                        return;
                                    }
                                    signedRequest.applyProfile(dialog.getProfile());
                                }
                                messages[0].setRequest(signedRequest.getSignedRequestBytes(profile.getCredential()));
                            }
                        });
                        addSignatureMenu.add(sigItem);
                    }
                    list.add(addSignatureMenu);
                }
                else if ((messages.length > 0) && (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) && isSigV4) {
                    JMenuItem editSignatureItem = new JMenuItem("Edit Signature");
                    editSignatureItem.addActionListener(new ActionListener()
                    {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent)
                        {
                            AWSSignedRequest signedRequest = new AWSSignedRequest(messages[0], BurpExtender.this);
                            final AWSProfile sigProfile = signedRequest.getAnonymousProfile(); // build profile from original request
                            final AWSProfile savedProfile = customizeSignedRequest(signedRequest); // get profile used to sign original request (if it exists)
                            if (savedProfile == null) {
                                // if existing profile doesn't exist with this key id, create one and apply it
                                AWSProfileEditorDialog dialog = new AWSProfileEditorDialog(null, "Add Profile", true, null, BurpExtender.this);
                                dialog.applyProfile(sigProfile); // auto fill fields gathered from original request
                                dialog.nameTextField.setText(""); // overwrite garbage value used to pass validation
                                dialog.secretKeyTextField.setText(""); // overwrite garbage value used to pass validation
                                callbacks.customizeUiComponent(dialog);
                                dialog.setVisible(true);
                                final AWSProfile newProfile = customizeSignedRequest(signedRequest);
                                if (newProfile != null) {
                                    signedRequest.applyProfile(newProfile);
                                    messages[0].setRequest(signedRequest.getSignedRequestBytes(newProfile.getCredential()));
                                } // else... XXX maybe display an error dialog here
                                return;
                            }
                            AWSProfile editedProfile = new AWSProfile.Builder(savedProfile) // get profile as saved by the accessKey
                            // some values may differ from what are saved for the profile, so set them here.
                                    .withRegion(sigProfile.getRegion())
                                    .withService(sigProfile.getService())
                                    .build();
                            AWSProfileEditorReadOnlyDialog dialog = new AWSProfileEditorReadOnlyDialog(null, "Edit Signature", true, editedProfile, BurpExtender.this);
                            callbacks.customizeUiComponent(dialog);
                            // disable profile name and secret since they will have to be changed in the top-level plugin tab.
                            // XXX would be nice to have a combobox for the profile here instead of disabling.
                            dialog.disableForEdit();
                            dialog.setVisible(true);
                            if (dialog.getProfile() != null) {
                                // if region or service are cleared in the dialog, they will not be applied here. must edit request manually instead.
                                signedRequest.applyProfile(dialog.getProfile());
                                messages[0].setRequest(signedRequest.getSignedRequestBytes(editedProfile.getCredential()));
                            }
                        }
                    });
                    list.add(editSignatureItem);
                }
        }
        return list;
    }

    // display status message in UI
    private void updateStatus(final String status)
    {
        logger.debug("Set Status: " + status);
        this.statusLabel.setText(status);
    }

    private List<String> getSortedProfileNames()
    {
        // sort by name in table
        List<String> profileNames = new ArrayList<>(this.profileNameMap.keySet());
        Collections.sort(profileNames);
        return profileNames;
    }

    /*
    call this when profile list changes
    */
    private void updateAwsProfilesUI()
    {
        DefaultTableModel model = (DefaultTableModel) this.profileTable.getModel();
        model.setRowCount(0); // clear table
        final String defaultProfileName = (String) defaultProfileComboBox.getSelectedItem();
        defaultProfileComboBox.removeAllItems();
        defaultProfileComboBox.addItem(NO_DEFAULT_PROFILE);

        // sort by name in table
        List<String> profileNames = getSortedProfileNames();

        for (final String name : profileNames) {
            AWSProfile profile = this.profileNameMap.get(name);
            model.addRow(new Object[]{profile.getName(), profile.getAccessKeyId(), profile.getActiveProvider().getName(), profile.getRegion(), profile.getService()});
            defaultProfileComboBox.addItem(name);
        }
        setDefaultProfileName(defaultProfileName);
    }


    protected void addProfile(AWSProfile profile)
    {
        // NOTE: validation check (via profile.isValid) is intentionally omitted here. This is so users can
        // deliberately specify invalid values for testing purposes.
        if (profile.getName().length() > 0) {
            AWSProfile p1 = this.profileNameMap.get(profile.getName());
            AWSProfile p2 = this.profileKeyIdMap.get(profile.getAccessKeyId());
            if ((p2 != null) && (p1 == null)) {
                updateStatus("Profiles must have a unique accessKeyId");
                throw new IllegalArgumentException("Profiles must have a unique accessKeyId");
            }
            // for accessKeyId updates, clean up the old id
            if (p1 != null) {
                if (this.profileKeyIdMap.containsKey(p1.getAccessKeyId())) {
                    this.profileKeyIdMap.remove(p1.getAccessKeyId());
                }
            }
            this.profileKeyIdMap.put(profile.getAccessKeyId(), profile);
            this.profileNameMap.put(profile.getName(), profile);
            updateAwsProfilesUI();
            if (p1 == null) {
                updateStatus("Added profile: " + profile.getName());
            }
            else {
                updateStatus("Saved profile: " + profile.getName());
            }
            return;
        }
        throw new IllegalArgumentException("AWSProfile name must not be blank");
    }

    /*
    if newProfile is valid, delete oldProfile and add newProfile.
     */
    protected void updateProfile(final AWSProfile oldProfile, final AWSProfile newProfile)
    {
        if (oldProfile == null) {
            addProfile(newProfile);
            return;
        }
        if (newProfile.getName().length() == 0) {
            throw new IllegalArgumentException("AWSProfile name must not be blank");
        }
        // remove any profile with same name
        AWSProfile p1 = this.profileNameMap.get(oldProfile.getName());
        AWSProfile p2 = this.profileKeyIdMap.get(oldProfile.getAccessKeyId());
        if ((p1 == null) || (p2 == null)) {
            updateStatus("Update profile failed. Old profile doesn't exist.");
            throw new IllegalArgumentException("Update profile failed. Old profile doesn't exist.");
        }
        deleteProfile(oldProfile);
        try {
            addProfile(newProfile);
        } catch (IllegalArgumentException exc) {
            addProfile(oldProfile); // oops. add old profile back
            throw exc;
        }
    }


    protected void deleteProfile(AWSProfile profile)
    {
        if (this.profileNameMap.containsKey(profile.getName())) {
            updateStatus(String.format("Deleted profile '%s'", profile.getName()));
        }
        this.profileKeyIdMap.remove(profile.getAccessKeyId());
        this.profileNameMap.remove(profile.getName());
        updateAwsProfilesUI();
    }

    /*
    Check if the request is for AWS. Can be POST or GET request.
    */
    public static boolean isAwsRequest(IRequestInfo request)
    {
        // all AWS requests require x-amz-date either in the query string or as a header. Date can be used but is not unique enough.
        // Consider adding additional check for Authorization header or X-Amz-Credential query string param - DONE
        // This routine needs to be fast since potentially ALL requests will cause an invocation.
        // https://docs.aws.amazon.com/general/latest/gr/sigv4-date-handling.html
        boolean hasAmzDate = false;
        boolean hasAmzCreds = false;
        for (String header : request.getHeaders()) {
            if (!hasAmzDate && header.toLowerCase().startsWith("x-amz-date:")) {
                hasAmzDate = true;
                if (hasAmzCreds) break;
            }
            else if (!hasAmzCreds && header.toLowerCase().startsWith("authorization:")) {
                hasAmzCreds = true;
                if (hasAmzDate) break;
            }
        }

        // we don't reset hasAmzDate/hasAmzCreds here even though parameters probably shouldn't be mixed.

        // check for query string parameters
        for (IParameter param : request.getParameters()) {
            if (!hasAmzDate && param.getName().toLowerCase().equals("x-amz-date")) {
                hasAmzDate = true;
                if (hasAmzCreds) break;
            }
            else if (!hasAmzCreds && param.getName().toLowerCase().equals("x-amz-credential")) {
                hasAmzCreds = true;
                if (hasAmzDate) break;
            }
        }

        return (hasAmzDate && hasAmzCreds);
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
        return Arrays.asList(additionalSignedHeadersField.getText().split(",+"))
                .stream()
                .map(h -> h.trim())
                .collect(Collectors.toList());
    }

    /* get the additional headers specified in the UI */
    private List<String> getCustomHeadersFromUI()
    {
        List<String> headers = new ArrayList<>();
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

    private void setCustomHeadersInUI(final List<String> customHeaders)
    {
        DefaultTableModel model = (DefaultTableModel) customHeadersTable.getModel();
        for (final String header : customHeaders) {
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
        AWSProfile profile = null;

        // check if the "X-BurpAwsig-Profile: PROFILE" header was used to specify a profile
        final String profileHeader = signedRequest.getProfileHeaderValue();
        if (profileHeader != null) {
            profile = this.profileNameMap.get(profileHeader);
            if (profile != null) {
                logger.debug("Using profile from header: "+profile.getName());
            }
            else {
                logger.debug("Profile from header not found: "+profileHeader);
            }
        }

        if (profile == null) {
            profile = getSigningProfile(signedRequest.getAccessKeyId());
        }

        if (profile == null) {
            logger.error("No profile found for accessKeyId: " + signedRequest.getAccessKeyId());
            return null;
        }

        // add any user-specified, custom HTTP headers
        signedRequest.addSignedHeaders(getCustomHeadersFromUI(), customHeadersOverwriteCheckbox.isSelected());

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
                AWSSignedRequest signedRequest = new AWSSignedRequest(messageInfo, this);
                final AWSProfile profile = customizeSignedRequest(signedRequest);
                if (profile == null) {
                    logger.error("Failed to apply custom settings to signed request");
                    return;
                }

                AWSCredential credential = profile.getCredential();
                if (credential == null) {
                    // assume role failure
                    logger.error("Failed to get credentials for profile: "+profile.getName());
                    return;
                }
                else {
                    byte[] requestBytes = signedRequest.getSignedRequestBytes(credential);
                    if (requestBytes != null) {
                        logger.info("Signed request with profile: " + profile);
                        messageInfo.setComment("SigV4 "+profile.getName());
                        messageInfo.setRequest(requestBytes);
                    }
                }
            }
        }
    }

}
