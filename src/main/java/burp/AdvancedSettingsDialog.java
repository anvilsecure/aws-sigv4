package burp;

import lombok.Getter;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;

public class AdvancedSettingsDialog extends JDialog {

    private static AdvancedSettingsDialog settingsDialog = null;
    private JLabel statusLabel;
    private static final String DEFAULT_STATUS_LABEL_TEXT = "Ok to submit";

    protected final JCheckBox signingEnabledForProxyCheckbox = new JCheckBox("Proxy");
    protected final JCheckBox signingEnabledForSpiderCheckBox = new JCheckBox("Spider");
    protected final JCheckBox signingEnabledForScannerCheckBox = new JCheckBox("Scanner");
    protected final JCheckBox signingEnabledForIntruderCheckBox = new JCheckBox("Intruder");
    protected final JCheckBox signingEnabledForRepeaterCheckBox = new JCheckBox("Repeater");
    protected final JCheckBox signingEnabledForSequencerCheckBox = new JCheckBox("Sequencer");
    protected final JCheckBox signingEnabledForExtenderCheckBox = new JCheckBox("Extender");

    @Getter private long presignedUrlLifetimeSeconds = ExtensionSettings.PRESIGNED_URL_LIFETIME_DEFAULT_SECONDS;
    private JTextField presignedUrlLifetimeTextField = new JTextField(Long.toString(ExtensionSettings.PRESIGNED_URL_LIFETIME_DEFAULT_SECONDS), 5);

    protected final JCheckBox preserveHeaderOrderCheckBox = new JCheckBox("Preserve Header Order");
    protected final JCheckBox updateContentSha256CheckBox = new JCheckBox("Update content-sha256 Header");
    protected final JCheckBox addProfileCommentCheckBox = new JCheckBox("Add Profile Comment");
    private final JComboBox<String> contentMD5HeaderBehaviorComboBox = new JComboBox<>();

    public String getContentMD5HeaderBehavior() {
        return contentMD5HeaderBehaviorComboBox.getSelectedItem().toString();
    }

    private AdvancedSettingsDialog(Frame owner, String title, boolean modal) {
        super(owner, title, modal);

        int outerPanelY = 0;
        JPanel outerPanel = new JPanel();
        outerPanel.setLayout(new GridBagLayout());

        JPanel toolPanel = new JPanel();
        toolPanel.setBorder(new TitledBorder("Tools Enabled for Signing"));
        toolPanel.add(signingEnabledForProxyCheckbox);
        toolPanel.add(signingEnabledForSpiderCheckBox);
        toolPanel.add(signingEnabledForScannerCheckBox);
        toolPanel.add(signingEnabledForIntruderCheckBox);
        toolPanel.add(signingEnabledForRepeaterCheckBox);
        toolPanel.add(signingEnabledForSequencerCheckBox);
        toolPanel.add(signingEnabledForExtenderCheckBox);
        GridBagConstraints c00 = new GridBagConstraints();
        c00.gridx = 0;
        c00.gridy = outerPanelY++;
        c00.anchor = GridBagConstraints.LINE_START;
        outerPanel.add(toolPanel, c00);

        JPanel miscPanel = new JPanel(new GridBagLayout());
        miscPanel.setBorder(new TitledBorder("Misc"));
        int miscPanelY = 0;
        JPanel miscComboBoxPanel = new JPanel();
        contentMD5HeaderBehaviorComboBox.addItem(ExtensionSettings.CONTENT_MD5_IGNORE);
        contentMD5HeaderBehaviorComboBox.addItem(ExtensionSettings.CONTENT_MD5_UPDATE);
        contentMD5HeaderBehaviorComboBox.addItem(ExtensionSettings.CONTENT_MD5_REMOVE);
        contentMD5HeaderBehaviorComboBox.setSelectedItem(ExtensionSettings.CONTENT_MD5_DEFAULT);
        miscComboBoxPanel.add(new JLabel("ContentMD5 Header Behavior"));
        miscComboBoxPanel.add(contentMD5HeaderBehaviorComboBox);
        miscComboBoxPanel.add(new JLabel("Presigned URL Lifetime Seconds"));
        miscComboBoxPanel.add(presignedUrlLifetimeTextField);

        JPanel miscCheckBoxPanel = new JPanel();
        miscCheckBoxPanel.add(preserveHeaderOrderCheckBox);
        miscCheckBoxPanel.add(updateContentSha256CheckBox);
        miscCheckBoxPanel.add(addProfileCommentCheckBox);

        GridBagConstraints cm00 = new GridBagConstraints(); cm00.gridx = 0; cm00.gridy = miscPanelY++; cm00.anchor = GridBagConstraints.LINE_START;
        GridBagConstraints cm01 = new GridBagConstraints(); cm01.gridx = 0; cm01.gridy = miscPanelY++; cm01.anchor = GridBagConstraints.LINE_START;
        miscPanel.add(miscComboBoxPanel, cm00);
        miscPanel.add(miscCheckBoxPanel, cm01);
        GridBagConstraints c03 = new GridBagConstraints();
        c03.gridx = 0;
        c03.gridy = outerPanelY++;
        c03.anchor = GridBagConstraints.LINE_START;
        outerPanel.add(miscPanel, c03);

        // import/export settings json with dialogs
        JPanel importExportPanel = new JPanel();
        JButton settingsImportButton = new JButton("Import");
        settingsImportButton.addActionListener(actionEvent -> {
            JDialog dialog = new JDialog((Frame)null, "Import Settings Json", true);
            JPanel mainPanel = new JPanel(new BorderLayout());
            JTextArea textPanel = new JTextArea();
            JScrollPane scrollPane = new JScrollPane(textPanel);
            mainPanel.add(scrollPane, BorderLayout.CENTER);
            JPanel buttonPanel = new JPanel();
            JButton okButton = new JButton("Ok");
            okButton.addActionListener(actionEvent1 -> {
                BurpExtender.getBurp().importExtensionSettingsFromJson(textPanel.getText());
                dialog.setVisible(false);
            });
            buttonPanel.add(okButton);
            JButton pasteButton = new JButton("Paste");
            pasteButton.addActionListener(actionEvent1 -> {
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                try {
                    textPanel.setText((String)clipboard.getData(DataFlavor.stringFlavor));
                } catch (UnsupportedFlavorException | IOException ignored) {
                }
            });
            buttonPanel.add(pasteButton);
            JButton cancelButton = new JButton("Cancel");
            cancelButton.addActionListener(actionEvent1 -> {
                dialog.setVisible(false);
            });
            buttonPanel.add(cancelButton);
            mainPanel.add(buttonPanel, BorderLayout.PAGE_END);
            dialog.add(mainPanel);
            dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
            // set dialog location and size
            final Point burpLocation = SwingUtilities.getWindowAncestor(BurpExtender.getBurp().getUiComponent()).getLocation();
            dialog.setLocation(burpLocation);
            dialog.setPreferredSize(SwingUtilities.getWindowAncestor(BurpExtender.getBurp().getUiComponent()).getBounds().getSize());
            dialog.pack();
            dialog.setVisible(true);
        });
        JButton settingsExportButton = new JButton("Export");
        settingsExportButton.addActionListener(actionEvent -> {
            // display settings json in a new dialog
            JDialog dialog = new JDialog((Frame)null, "Export Settings Json", true);
            JPanel mainPanel = new JPanel(new BorderLayout());
            JTextArea textPanel = new JTextArea();
            textPanel.setText(BurpExtender.getBurp().exportExtensionSettingsToJson());
            textPanel.setCaretPosition(0); // scroll to top
            textPanel.setEditable(false);
            JScrollPane scrollPane = new JScrollPane(textPanel);
            mainPanel.add(scrollPane, BorderLayout.CENTER);
            JPanel buttonPanel = new JPanel();
            JButton copyToClipboardButton = new JButton("Copy to clipboard");
            copyToClipboardButton.addActionListener(actionEvent12 -> {
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(new StringSelection(textPanel.getText()), null);
            });
            buttonPanel.add(copyToClipboardButton);
            JButton closeButton = new JButton("Close");
            closeButton.addActionListener(actionEvent1 -> {
                dialog.setVisible(false);
            });
            buttonPanel.add(closeButton);
            mainPanel.add(buttonPanel, BorderLayout.PAGE_END);
            dialog.add(mainPanel);
            dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
            // place dialog in upper left of burp window
            final Point burpLocation = SwingUtilities.getWindowAncestor(BurpExtender.getBurp().getUiComponent()).getLocation();
            dialog.setLocation(burpLocation);
            // make sure dialog height and width do not exceed burp window height and width
            final int height = SwingUtilities.getWindowAncestor(BurpExtender.getBurp().getUiComponent()).getBounds().getSize().height;
            final int width = SwingUtilities.getWindowAncestor(BurpExtender.getBurp().getUiComponent()).getBounds().getSize().width;
            dialog.pack();
            dialog.setSize(Integer.min(width, dialog.getSize().width), height);
            dialog.setVisible(true);
        });
        importExportPanel.setBorder(new TitledBorder("Settings JSON"));
        importExportPanel.add(settingsImportButton);
        importExportPanel.add(settingsExportButton);
        GridBagConstraints c02 = new GridBagConstraints();
        c02.gridx = 0;
        c02.gridy = outerPanelY++;
        c02.anchor = GridBagConstraints.LINE_START;
        outerPanel.add(importExportPanel, c02);

        // status message
        statusLabel = new JLabel(DEFAULT_STATUS_LABEL_TEXT);
        Font defaultFont = statusLabel.getFont();
        statusLabel.setFont(new Font(defaultFont.getFamily(), Font.ITALIC, defaultFont.getSize()));
        statusLabel.setForeground(BurpExtender.textOrange);
        GridBagConstraints c04 = new GridBagConstraints();
        c04.gridx = 0;
        c04.gridy = outerPanelY++;
        c04.anchor = GridBagConstraints.CENTER;
        outerPanel.add(statusLabel, c04);

        JPanel lowerButtonPanel = new JPanel();
        JButton okButton = new JButton("Ok");
        okButton.addActionListener(actionEvent -> {
            try {
                validateSettings();
                setVisible(false);
                statusLabel.setText(DEFAULT_STATUS_LABEL_TEXT);
            } catch (IllegalArgumentException e) {
                // TODO: line wrap
                statusLabel.setText(e.getMessage());
            }
            pack();
        });
        lowerButtonPanel.add(okButton);
        GridBagConstraints c01 = new GridBagConstraints();
        c01.gridx = 0;
        c01.gridy = outerPanelY++;
        c01.anchor = GridBagConstraints.PAGE_END;
        outerPanel.add(lowerButtonPanel, c01);

        add(outerPanel);
        pack();
    }

    // Validate settings updated in this dialog only. This dialog is initialized with values that should have already
    // been validated.
    //
    // Note that settings which require validation are not saved until validation succeeds ("Ok" button is pressed
    // and dialog disappears). Other settings take effect immediately (all check boxes and combo boxes).
    private void validateSettings() {
        long lifetime;
        try {
            lifetime = Long.parseLong(presignedUrlLifetimeTextField.getText());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Expected an integer for presigned URL lifetime");
        }

        if (lifetime < ExtensionSettings.PRESIGNED_URL_LIFETIME_MIN_SECONDS || lifetime > ExtensionSettings.PRESIGNED_URL_LIFETIME_MAX_SECONDS) {
            throw new IllegalArgumentException(String.format("Presigned URL lifetime must be between %d and %d, inclusive",
                    ExtensionSettings.PRESIGNED_URL_LIFETIME_MIN_SECONDS, ExtensionSettings.PRESIGNED_URL_LIFETIME_MAX_SECONDS));
        }
        presignedUrlLifetimeSeconds = lifetime;
    }

    public void applyExtensionSettings(final ExtensionSettings settings) {
        signingEnabledForProxyCheckbox.setSelected(settings.signingEnabledForProxy());
        signingEnabledForSpiderCheckBox.setSelected(settings.signingEnabledForSpider());
        signingEnabledForScannerCheckBox.setSelected(settings.signingEnabledForScanner());
        signingEnabledForIntruderCheckBox.setSelected(settings.signingEnabledForIntruder());
        signingEnabledForRepeaterCheckBox.setSelected(settings.signingEnabledForRepeater());
        signingEnabledForSequencerCheckBox.setSelected(settings.signingEnabledForSequencer());
        signingEnabledForExtenderCheckBox.setSelected(settings.signingEnabledForExtender());

        preserveHeaderOrderCheckBox.setSelected(settings.preserveHeaderOrder());
        updateContentSha256CheckBox.setSelected(settings.updateContentSha256());
        addProfileCommentCheckBox.setSelected(settings.addProfileComment());
        contentMD5HeaderBehaviorComboBox.setSelectedItem(settings.contentMD5HeaderBehavior());
        presignedUrlLifetimeSeconds = settings.presignedUrlLifetimeInSeconds();
    }

    // recenter the dialog every time
    public void setVisible(final boolean visible) {
        if (visible) {
            setLocationRelativeTo(BurpExtender.getBurp().getUiComponent());
        }
        super.setVisible(visible);
    }

    public static AdvancedSettingsDialog get() {
        if (settingsDialog == null) {
            settingsDialog = new AdvancedSettingsDialog(null, "Advanced Settings", true);
        }
        return settingsDialog;
    }
}
