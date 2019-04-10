package burp;

import javax.swing.*;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.util.List;


public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IExtensionStateListener
{
    private static String SETTING_PROFILES = "SerializedProfileList";

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter inf;
    private PrintWriter err;
    private HashMap<String, AWSProfile> profileKeyIdMap; // map accessKeyId to profile
    private HashMap<String, AWSProfile> profileNameMap; // map accessKeyId to profile

    private JPanel panel1;
    private JComboBox profileComboBox;
    private JTextField nameTextField;
    private JTextField accessKeyIdTextField;
    private JTextField secretKeyTextField;
    private JTextField regionTextField;
    private JTextField serviceTextField;
    private JCheckBox accessKeyIdcheckBox;
    private JCheckBox regionCheckBox;
    private JCheckBox serviceCheckBox;
    private JButton saveProfileButton;
    private JButton deleteProfileButton;
    private JButton importProfilesButton;
    private JLabel statusLabel;
    private JButton makeDefaultButton;
    private JCheckBox enabledCheckBox;
    private JComboBox defaultProfileComboBox;
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

        this.inf = new PrintWriter(callbacks.getStdout(), true);
        this.err = new PrintWriter(callbacks.getStderr(), true);

        this.profileKeyIdMap = new HashMap<>();
        this.profileNameMap = new HashMap<>();

        try {
            final String serializedProfileList = callbacks.loadExtensionSetting(SETTING_PROFILES);
            if (serializedProfileList != null) {
                ObjectInputStream objectIn = new ObjectInputStream(new ByteArrayInputStream(helpers.stringToBytes(serializedProfileList)));
                ArrayList<AWSProfile> profileList = (ArrayList<AWSProfile>) objectIn.readObject();
                objectIn.close();
                for (final AWSProfile profile : profileList) {
                    addProfile(profile);
                }
                this.inf.println(String.format("Loaded %s profiles", profileList.size()));
            }
        } catch (Exception exc) {
            this.err.println("Failed to load saved profiles");
        }

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                callbacks.registerHttpListener(BurpExtender.this);
                callbacks.addSuiteTab(BurpExtender.this);

                contextMenu = new AWSContextMenu(BurpExtender.this);
                callbacks.registerContextMenuFactory(contextMenu);

                setupPanel();
                enabledCheckBox.setSelected(true);

                inf.println("Loaded AWSig");
            }
        });
    }

    @Override
    public void extensionUnloaded()
    {
        ArrayList<AWSProfile> awsProfiles = new ArrayList<>();
        for (final String name : this.profileNameMap.keySet()) {
            awsProfiles.add(this.profileNameMap.get(name));
        }
        if (awsProfiles.size() > 0) {
            try {
                ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
                ObjectOutputStream objectOut = new ObjectOutputStream(bytesOut);
                objectOut.writeObject(awsProfiles);
                objectOut.close();
                final String serializedProfileList = this.helpers.bytesToString(bytesOut.toByteArray());
                this.callbacks.saveExtensionSetting(SETTING_PROFILES, serializedProfileList);
                this.inf.println(String.format("Saved %d profiles", awsProfiles.size()));
            } catch (Exception exc) {
                this.err.println("Failed to save AWS profiles");
            }
        }
        this.inf.println("Unloading AWSig");
    }

    public List<JMenuItem> getContextMenuItems() {
        JMenu menu = new JMenu("AWSig");

        JRadioButtonMenuItem item = new JRadioButtonMenuItem("Disable AWSig", !isEnabled());
        item.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                enabledCheckBox.setSelected(false);
            }
        });
        menu.add(item);
        for (final String name : this.profileNameMap.keySet()) {
            item = new JRadioButtonMenuItem(name, isEnabled() && name.equals(getDefaultProfileName()));
            item.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    JRadioButtonMenuItem item = (JRadioButtonMenuItem)actionEvent.getSource();
                    enabledCheckBox.setSelected(true);
                    //inf.println(String.format("MenuItem '%s' is selected = '%s'", item.getText(), item.isSelected() ? "yes" : "no"));
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
        return "AWSig";
    }

    @Override
    public Component getUiComponent() {
        return panel1;
    }

    private AWSProfile profileFromCurrentForm()
    {
        return new AWSProfile(nameTextField.getText(), accessKeyIdTextField.getText(), accessKeyIdcheckBox.isSelected(),
            secretKeyTextField.getText(), regionTextField.getText(), regionCheckBox.isSelected(), serviceTextField.getText(),
            serviceCheckBox.isSelected(),true);
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

    }

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
            if (name.equals(defaultProfileName)) {
                this.defaultProfileComboBox.setSelectedIndex(this.defaultProfileComboBox.getItemCount() - 1);
            }
        }
        updateForm(this.nameTextField.getText());
    }

    private void clearForm()
    {
        this.nameTextField.setText("");
        this.accessKeyIdTextField.setText("");
        this.secretKeyTextField.setText("");
        this.regionTextField.setText("");
        this.serviceTextField.setText("");

        this.accessKeyIdcheckBox.setSelected(false);
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

        this.accessKeyIdcheckBox.setSelected(profile.accessKeyIdAuto);
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
        Path credPath = Paths.get(System.getProperty("user.home") + "/.aws/credentials");
        if (!Files.exists(credPath)) {
            JFileChooser chooser = new JFileChooser(System.getProperty("user.home"));
            chooser.setFileHidingEnabled(false);
            if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                credPath = Paths.get(chooser.getSelectedFile().getPath());
            } else {
                return;
            }
        }
        inf.println("Importing AWS credentials from: " + credPath.toString());

        int count = 0;
        for (AWSProfile profile : AWSProfile.fromCredentialPath(credPath)) {
            if (addProfile(profile)) {
                inf.println("Imported profile: "+profile);
                count += 1;
            }
        }
        updateStatus(String.format("Imported %d profiles", count));
    }

    /*
    Check if the request is for AWS. Can be POST or GET request.
    */
    private boolean isAwsRequest(IRequestInfo request) {
        // all AWS requests require x-amz-date either in the query string or as a header
        for (String header : request.getHeaders()) {
            if (header.toLowerCase().startsWith("x-amz-date:")) {
                return true;
            }
        }

        for (IParameter param : request.getParameters()) {
            if (param.getName().toLowerCase().equals("x-amz-date")) {
                return true;
            }
        }

        return false;
    }

    private void printHeaders(IRequestInfo request)
    {
        inf.println("Request Parameters");
        for (IParameter param : request.getParameters()) {
            inf.println(String.format("%s = %s", param.getName(), param.getValue()));
        }
        inf.println("Request Headers");
        for (String header : request.getHeaders()) {
            inf.println("+"+header);
        }
    }

    private String getDefaultProfileName()
    {
        final String defaultProfileName = (String)this.defaultProfileComboBox.getSelectedItem();
        if ((defaultProfileName == null) || (defaultProfileName.equals(""))) {
            return "";
        }
        return defaultProfileName;
    }

    private boolean setDefaultProfileName(final String defaultProfileName)
    {
        for (int i = 0; i < this.defaultProfileComboBox.getItemCount(); i++) {
            if (this.defaultProfileComboBox.getItemAt(i).equals(defaultProfileName)) {
                this.defaultProfileComboBox.setSelectedIndex(i);
                return true;
            }
        }
        return false;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        if (messageIsRequest && enabledCheckBox.isSelected()) {
            IRequestInfo request = helpers.analyzeRequest(messageInfo);
            if (isAwsRequest(request)) {
                inf.println("**************Got an AWS request**************");
                //printHeaders(request);

                AWSSignedRequest signedRequest = new AWSSignedRequest(messageInfo, this.callbacks);
                AWSProfile profile = this.profileNameMap.get(getDefaultProfileName());
                if (profile == null) {
                    profile = this.profileKeyIdMap.get(signedRequest.getAccessKeyId());
                    if (profile == null) {
                        inf.println("No profile found for accessKeyId: " + signedRequest.getAccessKeyId());
                        return;
                    }
                }

                signedRequest.applyProfile(profile);
                byte[] requestBytes = signedRequest.getSignedRequestBytes(profile.secretKey);

                inf.println("Signed request with profile: "+profile);
                if (requestBytes != null) {
                    inf.println("Request has been modified");
                    messageInfo.setRequest(requestBytes);
                }
            }
        }
    }

}