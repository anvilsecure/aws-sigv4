package burp;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.signer.Aws4Signer;
import software.amazon.awssdk.auth.signer.AwsS3V4Signer;
import software.amazon.awssdk.auth.signer.params.Aws4PresignerParams;
import software.amazon.awssdk.auth.signer.params.Aws4SignerParams;
import software.amazon.awssdk.auth.signer.params.AwsS3V4SignerParams;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;
import software.amazon.awssdk.services.sts.model.StsException;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Type;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;


public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IExtensionStateListener, IMessageEditorTabFactory, IContextMenuFactory
{
    private static final String EXTENSION_VERSION = "1.2.2";

    private static final String BURP_SETTINGS_KEY = "JsonSettings";
    private static final String SETTING_VERSION = "ExtensionVersion";
    private static final String SETTING_PROFILES = "SerializedProfileList";
    private static final String SETTING_PERSISTENT_PROFILES = "PersistentProfiles";
    private static final String SETTING_EXTENSION_ENABLED = "ExtensionEnabled";
    private static final String SETTING_DEFAULT_PROFILE_NAME = "DefaultProfileName";
    private static final String SETTING_LOG_LEVEL = "LogLevel";
    private static final String SETTING_CUSTOM_HEADERS = "CustomSignedHeaders";
    private static final String SETTING_CUSTOM_HEADERS_OVERWRITE = "CustomSignedHeadersOverwrite";
    private static final String SETTING_ADDITIONAL_SIGNED_HEADER_NAMES = "AdditionalSignedHeaderNames";
    private static final String SETTING_IN_SCOPE_ONLY = "InScopeOnly";
    private static final String SETTING_PRESERVE_HEADER_ORDER = "PreserveHeaderOrder";

    public static final String EXTENSION_NAME = "SigV4"; // Name in extender menu
    public static final String DISPLAY_NAME = "SigV4"; // name for tabs, menu, and other UI components
    private static final long PRESIGN_DURATION_SECONDS = 900; // pre-signed url lifetime

    private static final String NO_DEFAULT_PROFILE = "        "; // ensure combobox is visible. AWSProfile.profileNamePattern doesn't allow this name
    private static final String PROFILE_HEADER_NAME = "X-BurpSigV4-Profile".toLowerCase();
    private static final Pattern authorizationHeaderRegex = Pattern.compile("^Authorization: AWS4-HMAC-SHA256 Credential=(?<accessKeyId>[\\w]{16,128})/(?<date>[0-9]{8})/(?<region>[a-z0-9-]{5,64})/(?<service>[a-z0-9-]{1,64})/aws4_request, SignedHeaders=(?<headers>[\\w;-]+), Signature=[a-z0-9]{64}$", Pattern.CASE_INSENSITIVE);
    private static final Pattern authorizationHeaderLooseRegex = Pattern.compile("^Authorization:\\s+AWS4-HMAC-SHA256\\s+Credential=(?<accessKeyId>[\\w-]{0,128})/(?<date>[\\w-]{0,8})/(?<region>[\\w-]{0,64})/(?<service>[\\w-]{0,64})/aws4_request,\\s+SignedHeaders=(?<headers>[\\w;-]+),\\s+Signature=[\\w-]{0,64}$", Pattern.CASE_INSENSITIVE);

    protected IExtensionHelpers helpers;
    protected IBurpExtenderCallbacks callbacks;
    private HashMap<String, AWSProfile> profileKeyIdMap; // map accessKeyId to profile
    private HashMap<String, AWSProfile> profileNameMap; // map name to profile
    protected LogWriter logger = LogWriter.getLogger();
    private boolean preserveHeaderOrder = true; // preserve order of headers after signing

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
        customHeadersLabel.setForeground(textOrange);
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
                JDialog dialog = new AWSProfileEditorDialog(null, "Add Profile", true, null);
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
                    JDialog dialog = new AWSProfileEditorDialog(null, "Edit Profile", true, profileNameMap.get(name));
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
                // Test credentials by making a request to sts:GetCallerIdentity
                int[] rowIndeces = profileTable.getSelectedRows();
                DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
                if (rowIndeces.length == 1) {
                    final String name = (String) model.getValueAt(rowIndeces[0], 0);
                    AWSProfile profile = profileNameMap.get(name);
                    StsClient stsClient = StsClient.builder()
                            .region(Region.US_EAST_1)
                            .credentialsProvider(() -> {
                                final AWSCredential cred = profile.getCredential();
                                return AwsBasicCredentials.create(cred.getAccessKeyId(), cred.getSecretKey());
                            })
                            .build();

                    try {
                        GetCallerIdentityResponse response = stsClient.getCallerIdentity();
                        JDialog dialog = new ProfileTestDialog(null, profile, false, response);
                        dialog.setVisible(true);
                    } catch (StsException exc) {
                        JOptionPane.showMessageDialog(getUiComponent(), exc.getMessage());
                    }
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
                    AWSProfileImportDialog importDialog = new AWSProfileImportDialog(null, "Import Profiles", true);
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

        callbacks.setExtensionName(EXTENSION_NAME);
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
                logger.info(String.format("Loaded %s %s", EXTENSION_NAME, EXTENSION_VERSION));
            }
        });
    }

    /*
    build Gson object for de/serialization of settings. AWSCredential, AWSCredentialProvider, and Path need
    to be handled as a special case since they're interfaces.
     */
    private Gson getGsonSerializer()
    {
        return new GsonBuilder()
                .registerTypeAdapter(AWSCredential.class, new AWSCredentialSerializer())
                .registerTypeAdapter(AWSCredentialProvider.class, new AWSCredentialProviderSerializer())
                .registerTypeHierarchyAdapter(Path.class, new TypeAdapter<Path>() {
                    @Override
                    public void write(JsonWriter out, Path value) throws IOException {
                        if (value == null)
                            out.nullValue();
                        else
                            out.value(value.toString());
                    }

                    @Override
                    public Path read(JsonReader in) throws IOException {
                        return Paths.get(in.nextString());
                    }
                })
                .create();
    }

    private void saveExtensionSettings()
    {
        this.callbacks.saveExtensionSetting(SETTING_LOG_LEVEL, Integer.toString(this.logger.getLevel()));
        this.callbacks.saveExtensionSetting(SETTING_VERSION, EXTENSION_VERSION);

        HashMap<String, Object> settings = new HashMap<>();
        settings.put(SETTING_PERSISTENT_PROFILES, this.persistProfilesCheckBox.isSelected());
        settings.put(SETTING_EXTENSION_ENABLED, this.signingEnabledCheckBox.isSelected());
        settings.put(SETTING_DEFAULT_PROFILE_NAME, this.getDefaultProfileName());
        settings.put(SETTING_CUSTOM_HEADERS, getCustomHeadersFromUI());
        settings.put(SETTING_CUSTOM_HEADERS_OVERWRITE, this.customHeadersOverwriteCheckbox.isSelected());
        settings.put(SETTING_ADDITIONAL_SIGNED_HEADER_NAMES, getAdditionalSignedHeadersFromUI());
        settings.put(SETTING_IN_SCOPE_ONLY, this.inScopeOnlyCheckBox.isSelected());
        settings.put(SETTING_PRESERVE_HEADER_ORDER, this.preserveHeaderOrder);
        this.callbacks.saveExtensionSetting(BURP_SETTINGS_KEY, new Gson().toJson(settings));

        if (this.persistProfilesCheckBox.isSelected()) {
            Gson gson = getGsonSerializer();
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

        // load saved profiles
        final String profilesJsonString = this.callbacks.loadExtensionSetting(SETTING_PROFILES);
        if (profilesJsonString != null && !profilesJsonString.equals("")) {
            Gson gson = getGsonSerializer();
            final Type hashMapType = new TypeToken<HashMap<String, AWSProfile>>(){}.getType();
            Map<String, AWSProfile> profileMap;
            try {
                profileMap = gson.fromJson(profilesJsonString, hashMapType);
            } catch (JsonParseException exc) {
                logger.error("Failed to parse profile JSON");
                // overwrite invalid settings
                this.callbacks.saveExtensionSetting(SETTING_PROFILES, "{}");
                profileMap = new HashMap<>();
            }
            for (final String name : profileMap.keySet()) {
                try {
                    addProfile(profileMap.get(name));
                } catch (IllegalArgumentException exc) {
                    logger.error("Failed to add profile: "+name);
                }
            }
        }

        final String jsonSettingsString = this.callbacks.loadExtensionSetting(BURP_SETTINGS_KEY);
        if (jsonSettingsString == null || jsonSettingsString.equals("")) {
            logger.info("No plugin settings found");
        }
        else {
            JsonObject settings = new Gson().fromJson(jsonSettingsString, JsonObject.class);
            if (settings.has(SETTING_DEFAULT_PROFILE_NAME))
                setDefaultProfileName(settings.get(SETTING_DEFAULT_PROFILE_NAME).getAsString());
            else
                setDefaultProfileName(NO_DEFAULT_PROFILE);
            if (settings.has(SETTING_PERSISTENT_PROFILES))
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
            if (settings.has(SETTING_PRESERVE_HEADER_ORDER))
                this.preserveHeaderOrder = settings.get(SETTING_PRESERVE_HEADER_ORDER).getAsBoolean();
        }

    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        return new AWSMessageEditorTab(controller, editable);
    }

    @Override
    public void extensionUnloaded()
    {
        saveExtensionSettings();
        logger.info("Unloading "+EXTENSION_NAME);
    }

    @Override
    public String getTabCaption()
    {
        return DISPLAY_NAME;
    }

    @Override
    public Component getUiComponent()
    {
        return outerScrollPane;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)
    {
        JMenu menu = new JMenu(DISPLAY_NAME);

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

                // get signature properties from authorization header. this will return empty strings if validation fails.
                List <String> authorizationHeaders = requestInfo.getHeaders().stream()
                        .filter(h -> h.toLowerCase().startsWith("authorization:")).collect(Collectors.toList());
                Map<String, String> authorizationMap = parseSigV4AuthorizationHeader(
                        (authorizationHeaders.size() > 0) ? authorizationHeaders.get(0) : "", false);
                // assume sigv4 if any values were successfully parsed from the authorization header
                final boolean isSigV4 = authorizationMap.values().stream().anyMatch(v -> v.length() > 0);

                if ((messages.length > 0) && requestInfo.getMethod().toUpperCase().equals("GET") && authorizationMap.get("service").toLowerCase().equals("s3")) {
                    JMenuItem signedUrlItem = new JMenuItem("Copy Signed URL");
                    signedUrlItem.addActionListener(new ActionListener()
                    {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent)
                        {
                            final AWSProfile profile = getSigningProfile(requestInfo.getHeaders());
                            String signedUrl = ""; // clear clipboard on error
                            if (profile == null) {
                                // XXX consider notifying user of error
                                logger.error("Failed to determine signing profile");
                            }
                            else {
                                // sign a url valid for ? seconds. XXX consider making this configurable.
                                signedUrl = presignRequest(messages[0].getHttpService(), messages[0].getRequest(), profile).toString();
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
                        sigItem.setActionCommand(name);
                        sigItem.addActionListener(new ActionListener()
                        {
                            @Override
                            public void actionPerformed(ActionEvent actionEvent)
                            {
                                final String profileName = actionEvent.getActionCommand();
                                AWSProfile profile = profileNameMap.get(profileName);
                                if (profile == null) {
                                    // XXX maybe use an "Add Profile" dialog here?
                                    logger.error("Profile name does not exist: "+profileName);
                                    return;
                                }
                                // if region or service is missing, prompt user. do not re-prompt if values are left blank
                                if (profile.getService().equals("") || profile.getRegion().equals("")) {
                                    AWSProfileEditorReadOnlyDialog dialog = new AWSProfileEditorReadOnlyDialog(null, "Add Signature", true, profile);
                                    callbacks.customizeUiComponent(dialog);
                                    dialog.disableForEdit();
                                    // set focus to first missing field
                                    if (profile.getRegion().equals("")) {
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
                                    profile = dialog.getProfile();
                                }
                                try {
                                    messages[0].setRequest(signRequest(messages[0].getHttpService(), messages[0].getRequest(), profile));
                                } catch (IllegalArgumentException exc) {
                                    logger.error("Failed to add signature: "+exc.getMessage());
                                }
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
                            IRequestInfo requestInfo = helpers.analyzeRequest(messages[0]);
                            AWSProfile signingProfile = null;
                            final List<String> authorizationHeaders = requestInfo.getHeaders().stream()
                                    .filter(h -> h.toLowerCase().startsWith("authorization:"))
                                    .collect(Collectors.toList());
                            for (final String value : authorizationHeaders) {
                                Matcher matcher = authorizationHeaderRegex.matcher(value);
                                if (matcher.matches()) {
                                    AWSProfile tempProfile = profileKeyIdMap.get(matcher.group("accessKeyId"));
                                    if (tempProfile != null) {
                                        AWSProfile.Builder builder = new AWSProfile.Builder(tempProfile);
                                        if (tempProfile.getService().equals("")) {
                                            builder.withService(matcher.group("service"));
                                        }
                                        if (tempProfile.getRegion().equals("")) {
                                            builder.withRegion(matcher.group("region"));
                                        }
                                        signingProfile = builder.build();
                                        break;
                                    }
                                }
                            }
                            if (signingProfile == null) {
                                // request is likely invalid SigV4 format
                                AWSProfileEditorDialog dialog = new AWSProfileEditorDialog(null, "Add Profile", true, null);
                                List<Map<String, String>> signatures = authorizationHeaders.stream()
                                        .map(h -> parseSigV4AuthorizationHeader(h, false))
                                        .filter(Objects::nonNull)
                                        .collect(Collectors.toList());
                                if (signatures.size() > 0) {
                                    dialog.profileKeyIdTextField.setText(signatures.get(0).get("accessKeyId"));
                                    dialog.serviceTextField.setText(signatures.get(0).get("service"));
                                    dialog.regionTextField.setText(signatures.get(0).get("region"));
                                }
                                dialog.setVisible(true);
                                final String newProfileName = dialog.getNewProfileName();
                                if (newProfileName != null) {
                                    final AWSProfile newProfile = profileNameMap.get(newProfileName);
                                    if (newProfile != null) {
                                        messages[0].setRequest(signRequest(messages[0].getHttpService(), messages[0].getRequest(), newProfile));
                                    } // else... XXX maybe display an error dialog here
                                }
                            }
                            else {
                                AWSProfileEditorReadOnlyDialog dialog = new AWSProfileEditorReadOnlyDialog(null, "Edit Signature", true, signingProfile);
                                callbacks.customizeUiComponent(dialog);
                                // disable profile name and secret since they will have to be changed in the top-level plugin tab.
                                // XXX would be nice to have a combobox for the profile here instead of disabling.
                                dialog.disableForEdit();
                                dialog.setVisible(true);
                                if (dialog.getProfile() != null) {
                                    // if region or service are cleared in the dialog, they will not be applied here. must edit request manually instead.
                                    messages[0].setRequest(signRequest(messages[0].getHttpService(), messages[0].getRequest(), dialog.getProfile()));
                                }
                            }
                        }
                    });
                    list.add(editSignatureItem);
                }
        }
        return list;
    }

    private Map<String, String> parseSigV4AuthorizationHeader(final String header, final boolean validate)
    {
        Map<String, String> auth = null;
        Pattern pattern = authorizationHeaderLooseRegex;
        if (validate) {
            pattern = authorizationHeaderRegex;
        }
        Matcher matcher = pattern.matcher(header);
        if (matcher.matches()) {
            auth = Map.of(
                    "accessKeyId", matcher.group("accessKeyId"),
                    "date", matcher.group("date"),
                    "region", matcher.group("region"),
                    "service", matcher.group("service"),
                    "headers", matcher.group("headers")
            );
        }
        else if (!validate) {
            auth = Map.of(
                    "accessKeyId", "",
                    "date", "",
                    "region", "",
                    "service", "",
                    "headers", ""
            );
        }
        return auth;
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

        for (final String name : getSortedProfileNames()) {
            AWSProfile profile = this.profileNameMap.get(name);
            model.addRow(new Object[]{profile.getName(), profile.getAccessKeyIdForProfileSelection(), profile.getActiveProvider().getName(), profile.getRegion(), profile.getService()});
            defaultProfileComboBox.addItem(name);
        }
        setDefaultProfileName(defaultProfileName);
    }

    /*
    NOTE: this will overwrite an existing profile with the same name
    */
    protected void addProfile(final AWSProfile profile)
    {
        final AWSProfile p1 = this.profileNameMap.get(profile.getName());
        if (p1 == null) {
            // profile name doesn't exist. make sure there is no keyId conflict with an existing profile
            if (profile.getAccessKeyIdForProfileSelection() != null) {
                AWSProfile p2 = this.profileKeyIdMap.get(profile.getAccessKeyIdForProfileSelection());
                if (p2 != null) {
                    // keyId conflict. do not add profile
                    updateStatus("Profiles must have a unique accessKeyId: "+profile.getName());
                    throw new IllegalArgumentException(String.format("Profiles must have a unique accessKeyId: %s = %s", profile.getName(), p2.getName()));
                }
            }
        }

        this.profileNameMap.put(profile.getName(), profile);

        // refresh the keyId map
        this.profileKeyIdMap.clear();
        for (final AWSProfile p : this.profileNameMap.values()) {
            if (p.getAccessKeyIdForProfileSelection() != null) {
                this.profileKeyIdMap.put(p.getAccessKeyIdForProfileSelection(), p);
            }
        }

        updateAwsProfilesUI();
        if (p1 == null) {
            updateStatus("Added profile: " + profile.getName());
        }
        else {
            updateStatus("Saved profile: " + profile.getName());
        }
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

        // remove any profile with same name
        final AWSProfile p1 = this.profileNameMap.get(oldProfile.getName());
        if (p1 == null) {
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

    private void deleteProfile(AWSProfile profile)
    {
        if (this.profileNameMap.containsKey(profile.getName())) {
            this.profileNameMap.remove(profile.getName());
            updateStatus(String.format("Deleted profile '%s'", profile.getName()));
        }
        if (profile.getAccessKeyIdForProfileSelection() != null) {
            this.profileKeyIdMap.remove(profile.getAccessKeyIdForProfileSelection());
        }
        updateAwsProfilesUI();
    }

    /*
    Check if the request is signed with SigV4. Not a strict check.
    This routine needs to be fast since potentially ALL requests will cause an invocation.
    https://docs.aws.amazon.com/general/latest/gr/sigv4-date-handling.html
    */
    public static boolean isAws4Request(IRequestInfo request)
    {
        return request.getHeaders().stream().anyMatch(h -> h.toLowerCase().startsWith("authorization: aws4-hmac-sha256")) ||
                request.getParameters().stream().anyMatch(p -> p.getName().toLowerCase().equals("x-amz-credential"));
    }

    private String getDefaultProfileName()
    {
        String defaultProfileName = (String) this.defaultProfileComboBox.getSelectedItem();
        if (defaultProfileName == null) {
            defaultProfileName = NO_DEFAULT_PROFILE;
        }
        return defaultProfileName;
    }

    /*
    Note that no check is done on profile name. It is assumed values come from AWSProfile and are validated there.
     */
    private void setDefaultProfileName(final String defaultProfileName)
    {
        if (defaultProfileName != null) {
            for (int i = 0; i < this.defaultProfileComboBox.getItemCount(); i++) {
                if (this.defaultProfileComboBox.getItemAt(i).equals(defaultProfileName)) {
                    this.defaultProfileComboBox.setSelectedIndex(i);
                    //updateStatus("Default profile changed.");
                    return;
                }
            }
        }
        // possible if persistProfiles was set to false and default profile was not saved
    }

    private List<String> getAdditionalSignedHeadersFromUI()
    {
        return Arrays.asList(additionalSignedHeadersField.getText().split(",+"))
                .stream()
                .map(String::trim)
                .filter(h -> h.length() > 0)
                .collect(Collectors.toList());
    }

    /* get the additional headers specified in the UI */
    private List<String> getCustomHeadersFromUI()
    {
        List<String> headers = new ArrayList<>();
        DefaultTableModel model = (DefaultTableModel) customHeadersTable.getModel();
        for (int i = 0; i < model.getRowCount(); i++) {
            final String name = ((String) model.getValueAt(i, 0)).trim();
            final String value = ((String) model.getValueAt(i, 1)).trim();
            if (name.length() > 0) { // skip empty header names
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

    public AWSProfile getSigningProfile(List<String> headers)
    {
        // check for http header that specifies a signing profile
        AWSProfile signingProfile = headers.stream()
                .filter(h -> h.toLowerCase().startsWith(PROFILE_HEADER_NAME+":"))
                .map(h -> this.profileNameMap.get(splitHeader(h)[1]))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);

        // default profile has next highest priority
        if (signingProfile == null) {
            signingProfile = this.profileNameMap.get(getDefaultProfileName());
        }

        // if still cannot determine profile, find matching accessKeyId
        final List<String> authorizationHeaders = headers.stream()
                .filter(h -> h.toLowerCase().startsWith("authorization:"))
                .collect(Collectors.toList());
        for (final String value : authorizationHeaders) {
            Matcher matcher = authorizationHeaderRegex.matcher(value);
            if (matcher.matches()) {
                if (signingProfile == null) {
                    signingProfile = this.profileKeyIdMap.get(matcher.group("accessKeyId"));
                }

                AWSProfile.Builder builder = new AWSProfile.Builder(signingProfile);
                if (signingProfile.getService().equals("")) {
                    builder.withService(matcher.group("service"));
                }
                if (signingProfile.getRegion().equals("")) {
                    builder.withRegion(matcher.group("region"));
                }
                signingProfile = builder.build();
                break;
            }
        }

        return signingProfile;
    }

    /*
     Always returns an array of size 2 even if value is empty string.
     Name and value are trimmed of whitespace.
     */
    private String[] splitHeader(final String header)
    {
        List<String> tokens = Arrays.stream(header.split(":", 2))
                .map(String::trim)
                .collect(Collectors.toList());
        if (tokens.size() < 2) {
            return new String[]{tokens.get(0), ""};
        }
        return new String[]{tokens.get(0), tokens.get(1)};
    }

    private boolean shouldDoubleUrlEncodeForService(final String service)
    {
        //TODO track which services require double-encoding
        return false;
    }

    public byte[] signRequest(final IHttpService httpService, final byte[] originalRequestBytes, final AWSProfile signingProfile)
    {
        IRequestInfo request = helpers.analyzeRequest(httpService, originalRequestBytes);
        // parse authorization header
        String region = "";
        String service = "";
        Set<String> signedHeaderSet = getAdditionalSignedHeadersFromUI().stream().map(String::toLowerCase).collect(Collectors.toSet());
        signedHeaderSet.add("host"); // always require host header

        for (final String header : request.getHeaders()) {
            if (header.toLowerCase().startsWith("authorization:")) {
                Matcher matcher = authorizationHeaderRegex.matcher(header);
                if (matcher.matches()) {
                    //accessKeyId = matcher.group("accessKeyId");
                    region = matcher.group("region");
                    service = matcher.group("service");
                    // get headers to sign
                    Arrays.stream(matcher.group("headers").split(";"))
                            .forEach(h -> signedHeaderSet.add(h.toLowerCase()));
                    break;
                }
            }
        }

        // build map of headers to sign. there are 4 checks:
        //   1) if header was signed in original request
        //   2) custom signed headers specified in UI
        //   3) name starts with "X-Amz-"
        //   4) additional signed header (name only) from UI
        Map<String, List<String>> signedHeaderMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Map<String, List<String>> unsignedHeaderMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        List<String> allHeaders = request.getHeaders();
        final String lineOne = allHeaders.remove(0);

        for (final String header : allHeaders) {
            final String[] tokens = splitHeader(header);
            final String name = tokens[0];
            final String value = tokens[1];
            // check for request header that specifies profile name to use and leave out of final request
            if (name.toLowerCase().equals(PROFILE_HEADER_NAME)) {
                continue;
            }
            if (signedHeaderSet.contains(name.toLowerCase()) || name.toLowerCase().startsWith("x-amz-")) {
                if (!signedHeaderMap.containsKey(name)) {
                    signedHeaderMap.put(name, new ArrayList<String>());
                }
                signedHeaderMap.get(name).add(value);
            }
            else if (!name.toLowerCase().startsWith("authorization")) {
                if (!unsignedHeaderMap.containsKey(name)) {
                    unsignedHeaderMap.put(name, new ArrayList<String>());
                }
                unsignedHeaderMap.get(name).add(value);
            }
        }
        for (final String header : getCustomHeadersFromUI()) {
            final String[] tokens = splitHeader(header);
            final String name = tokens[0];
            final String value = tokens[1];
            if (!signedHeaderMap.containsKey(name) || customHeadersOverwriteCheckbox.isSelected()) {
                signedHeaderMap.put(name, new ArrayList<String>());
            }
            signedHeaderMap.get(name).add(value);
        }

        //TODO error check
        final AWSCredential credential = signingProfile.getCredential();
        AwsCredentials awsCredentials;
        if (credential.isTemporary()) {
            awsCredentials = AwsSessionCredentials.create(credential.getAccessKeyId(), credential.getSecretKey(), ((AWSTemporaryCredential) credential).getSessionToken());
        }
        else {
            awsCredentials = AwsBasicCredentials.create(credential.getAccessKeyId(), credential.getSecretKey());
        }

        // if region or service are specified in the profile, override them from original request
        if (!signingProfile.getRegion().equals("")) {
            region = signingProfile.getRegion();
        }
        if (!signingProfile.getService().equals("")) {
            service = signingProfile.getService();
        }

        // build request object for signing
        URI uri;
        try {
            uri = request.getUrl().toURI();
        } catch (URISyntaxException exc) {
            logger.error("Bad URL for signature: "+request.getUrl());
            return null;
        }

        // s3 will complain about duplicate headers that the signer itself adds (e.g. X-Amz-Date)
        boolean signedPayload = false;
        if (service.toLowerCase().equals("s3")) {
            for (final String name : signedHeaderMap.keySet().stream().collect(Collectors.toList())) {
                if (name.toLowerCase().startsWith("x-amz-")) {
                    // check if original request had a signed payload
                    if (name.toLowerCase().equals("x-amz-content-sha256")) {
                        signedPayload = !signedHeaderMap.get("x-amz-content-sha256").get(0).toUpperCase().equals("UNSIGNED-PAYLOAD");
                    }
                    signedHeaderMap.remove(name);
                }
            }
        }

        final byte[] body = Arrays.copyOfRange(originalRequestBytes, request.getBodyOffset(), originalRequestBytes.length);
        final SdkHttpFullRequest awsRequest = SdkHttpFullRequest.builder()
                .headers(signedHeaderMap)
                .uri(uri)
                .method(SdkHttpMethod.fromValue(request.getMethod()))
                .contentStreamProvider(() -> new ByteArrayInputStream(body))
                .build();

        // sign the request. can throw IllegalArgumentException
        SdkHttpFullRequest signedRequest;
        if (service.toLowerCase().equals("s3")) {
            AwsS3V4SignerParams signerParams = AwsS3V4SignerParams.builder()
                    .awsCredentials(awsCredentials)
                    .signingRegion(Region.of(region))
                    .signingName(service)
                    .enablePayloadSigning(signedPayload)
                    .doubleUrlEncode(shouldDoubleUrlEncodeForService(service))
                    .build();
            signedRequest = AwsS3V4Signer.create().sign(awsRequest, signerParams);
        }
        else {
            Aws4SignerParams signerParams = Aws4SignerParams.builder()
                    .awsCredentials(awsCredentials)
                    .doubleUrlEncode(shouldDoubleUrlEncodeForService(service)) // service dependent
                    .signingRegion(Region.of(region))
                    .signingName(service)
                    .build();
            signedRequest = Aws4Signer.create().sign(awsRequest, signerParams);
        }

        // build final request to send
        List<String> finalHeaders = new ArrayList<>();
        for (final String name : signedRequest.headers().keySet()) {
            for (final String value : signedRequest.headers().get(name)) {
                finalHeaders.add(String.format("%s: %s", name, value));
            }
        }
        for (final String name : unsignedHeaderMap.keySet()) {
            for (final String value : unsignedHeaderMap.get(name)) {
                finalHeaders.add(String.format("%s: %s", name, value));
            }
        }

        if (preserveHeaderOrder) {
            Map<String, Integer> headerOrderMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            int i = 0;
            for (final String header : allHeaders) {
                headerOrderMap.putIfAbsent(splitHeader(header)[0], i++);
            }
            // sort new headers at the end
            Collections.sort(finalHeaders, Comparator.comparingInt(h -> headerOrderMap.getOrDefault(splitHeader(h)[0], finalHeaders.size())));
        }

        // add verb line back in after sorting
        finalHeaders.add(0, lineOne);

        final byte[] requestBytes = helpers.buildHttpMessage(finalHeaders, body);
        logger.debug("=======SIGNED REQUEST==========\n"+helpers.bytesToString(requestBytes));
        logger.debug("=======END REQUEST=============");
        return requestBytes;
    }

    public URL presignRequest(final IHttpService httpService, final byte[] originalRequestBytes, final AWSProfile signingProfile)
    {
        return presignRequest(httpService, originalRequestBytes, signingProfile, PRESIGN_DURATION_SECONDS);
    }

    public URL presignRequest(final IHttpService httpService, final byte[] originalRequestBytes, final AWSProfile signingProfile, final long durationSeconds)
    {

        IRequestInfo request = helpers.analyzeRequest(httpService, originalRequestBytes);
        // parse authorization header
        String region = "";
        String service = "";

        for (final String header : request.getHeaders()) {
            if (header.toLowerCase().startsWith("authorization:")) {
                Matcher matcher = authorizationHeaderRegex.matcher(header);
                if (matcher.matches()) {
                    region = matcher.group("region");
                    service = matcher.group("service");
                    break;
                }
            }
        }

        //TODO error check
        final AWSCredential credential = signingProfile.getCredential();
        AwsCredentials awsCredentials;
        if (credential.isTemporary()) {
            awsCredentials = AwsSessionCredentials.create(credential.getAccessKeyId(), credential.getSecretKey(), ((AWSTemporaryCredential) credential).getSessionToken());
        }
        else {
            awsCredentials = AwsBasicCredentials.create(credential.getAccessKeyId(), credential.getSecretKey());
        }

        // if region or service are specified in the profile, override them from original request
        if (!signingProfile.getRegion().equals("")) {
            region = signingProfile.getRegion();
        }
        if (!signingProfile.getService().equals("")) {
            service = signingProfile.getService();
        }

        // build request object for signing
        URI uri;
        try {
            uri = request.getUrl().toURI();
        } catch (URISyntaxException exc) {
            logger.error("Bad URL for signature: "+request.getUrl());
            return null;
        }

        final byte[] body = Arrays.copyOfRange(originalRequestBytes, request.getBodyOffset(), originalRequestBytes.length);
        final SdkHttpFullRequest awsRequest = SdkHttpFullRequest.builder()
                .uri(uri)
                .method(SdkHttpMethod.fromValue(request.getMethod()))
                .contentStreamProvider(() -> new ByteArrayInputStream(body))
                .build();

        // sign the request. can throw IllegalArgumentException
        SdkHttpFullRequest signedRequest;
        if (service.toLowerCase().equals("s3")) {
            Aws4PresignerParams signerParams = Aws4PresignerParams.builder()
                    .awsCredentials(awsCredentials)
                    .signingRegion(Region.of(region))
                    .signingName(service)
                    .doubleUrlEncode(shouldDoubleUrlEncodeForService(service))
                    .expirationTime(Instant.now().plusSeconds(durationSeconds))
                    .build();
            signedRequest = AwsS3V4Signer.create().presign(awsRequest, signerParams);
        }
        else {
            Aws4PresignerParams signerParams = Aws4PresignerParams.builder()
                    .awsCredentials(awsCredentials)
                    .doubleUrlEncode(shouldDoubleUrlEncodeForService(service))
                    .signingRegion(Region.of(region))
                    .signingName(service)
                    .expirationTime(Instant.now().plusSeconds(durationSeconds))
                    .build();
            signedRequest = Aws4Signer.create().presign(awsRequest, signerParams);
        }

        try {
            return signedRequest.getUri().toURL();
        } catch (MalformedURLException exc) {
            logger.error("Invalid pre-signed URL: "+signedRequest.getUri().toASCIIString());
        }
        return null;
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

            if (isAws4Request(request)) {
                final AWSProfile signingProfile = getSigningProfile(request.getHeaders());

                if (signingProfile == null) {
                    logger.error("Failed to get signing profile");
                    return;
                }

                final byte[] requestBytes = signRequest(messageInfo.getHttpService(), messageInfo.getRequest(), signingProfile);
                if (requestBytes != null) {
                    messageInfo.setRequest(requestBytes);
                    messageInfo.setComment(DISPLAY_NAME+" "+signingProfile.getName());
                }
            }
        }
    }

}
