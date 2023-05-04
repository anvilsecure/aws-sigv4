package burp;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

class NewSigProfile
{
    public String source;
    public SigProfile sigProfile;

    public NewSigProfile(SigProfile sigProfile, String source)
    {
        this.sigProfile = sigProfile;
        this.source = source;
    }
}

public class SigProfileImportDialog extends JDialog
{
    private static final int SELECT_COLUMN_INDEX = 0;
    private static final int NAME_COLUMN_INDEX = 1;
    private static final int KEYID_COLUMN_INDEX = 2;

    private BurpExtender burp = BurpExtender.getBurp();
    private JTable profileTable;
    private JLabel hintLabel;
    private HashMap<String, NewSigProfile> profileNameMap;

    public SigProfileImportDialog(Frame owner, String title, boolean modal)
    {
        super(owner, title, modal);
        this.profileNameMap = new HashMap<>();
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        JPanel outerPanel = new JPanel(new GridBagLayout());
        outerPanel.setBorder(new TitledBorder(""));

        // import from file buttons
        JPanel importButtonPanel = new JPanel();
        TitledBorder importBorder= new TitledBorder("Source");
        importBorder.setTitleColor(BurpExtender.textOrange);
        importButtonPanel.setBorder(importBorder);
        JButton autoImportButton = new JButton("Auto");
        JButton chooseImportButton = new JButton("File");
        JButton envImportButton = new JButton("Env");
        JButton shellImportButton = new JButton("Clipboard");
        importButtonPanel.add(autoImportButton);
        importButtonPanel.add(chooseImportButton);
        importButtonPanel.add(envImportButton);
        importButtonPanel.add(shellImportButton);

        autoImportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                final Path path = getAutoImportPath();
                if (path != null) {
                    importProfilesFromFile(path);
                }
                importProfilesFromEnvironment();
            }
        });

        chooseImportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                final Path path = getChosenImportPath();
                if (path != null) {
                    importProfilesFromFile(path);
                }
            }
        });

        envImportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                importProfilesFromEnvironment();
            }
        });

        shellImportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                importProfilesFromClipboard();
            }
        });

        // select all/none buttons
        JPanel selectButtonPanel = new JPanel();
        TitledBorder selectBorder = new TitledBorder("Select");
        selectBorder.setTitleColor(BurpExtender.textOrange);
        selectButtonPanel.setBorder(selectBorder);
        JButton selectAllButton = new JButton("All");
        JButton selectNoneButton = new JButton("None");
        selectButtonPanel.add(selectAllButton);
        selectButtonPanel.add(selectNoneButton);

        JPanel topButtonPanel = new JPanel();
        topButtonPanel.add(importButtonPanel);
        topButtonPanel.add(selectButtonPanel);

        selectAllButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
                for (int i = 0; i < model.getRowCount(); i++) {
                    model.setValueAt(true, i, SELECT_COLUMN_INDEX);
                }
            }
        });

        selectNoneButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
                for (int i = 0; i < model.getRowCount(); i++) {
                    model.setValueAt(false, i, SELECT_COLUMN_INDEX);
                }
            }
        });

        // import table
        profileTable = new JTable(new DefaultTableModel(new Object[]{"Import", "Name", "KeyId", "Source"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                // prevent table cells from being edited. must use dialog to edit.
                return column == SELECT_COLUMN_INDEX;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == SELECT_COLUMN_INDEX) {
                    return Boolean.class;
                }
                return super.getColumnClass(columnIndex);
            }
        });

        profileTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        profileTable.getColumnModel().getColumn(SELECT_COLUMN_INDEX).setMinWidth(60);
        profileTable.getColumnModel().getColumn(SELECT_COLUMN_INDEX).setMaxWidth(60);
        profileTable.getColumnModel().getColumn(NAME_COLUMN_INDEX).setMinWidth(150);
        profileTable.getColumnModel().getColumn(NAME_COLUMN_INDEX).setMaxWidth(300);
        profileTable.getColumnModel().getColumn(KEYID_COLUMN_INDEX).setMinWidth(220);
        profileTable.getColumnModel().getColumn(KEYID_COLUMN_INDEX).setMaxWidth(300);
        JScrollPane profileScrollPane = new JScrollPane(profileTable);
        profileScrollPane.setPreferredSize(new Dimension(900, 200));

        JPanel lowerButtonPanel = new JPanel();
        JButton okButton = new JButton("Ok");
        JButton cancelButton = new JButton("Cancel");
        lowerButtonPanel.add(okButton);
        lowerButtonPanel.add(cancelButton);

        okButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    addSelectedProfiles();
                } catch (IllegalArgumentException exc) {
                    hintLabel.setText(exc.getMessage());
                    return;
                }
                setVisible(false);
                dispose();
            }
        });

        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                setVisible(false);
                dispose();
            }
        });

        GridBagConstraints c00 = new GridBagConstraints();
        c00.anchor = GridBagConstraints.FIRST_LINE_START;
        c00.gridy = 0;
        GridBagConstraints c01 = new GridBagConstraints();
        c01.gridy = 1;
        GridBagConstraints c02 = new GridBagConstraints();
        c02.gridy = 2;
        GridBagConstraints c03 = new GridBagConstraints();
        c03.gridy = 3;
        hintLabel = new JLabel("Ok to import selected profiles");
        Font defaultFont = hintLabel.getFont();
        hintLabel.setFont(new Font(defaultFont.getFamily(), Font.ITALIC, defaultFont.getSize()));
        hintLabel.setForeground(BurpExtender.textOrange);
        outerPanel.add(topButtonPanel, c00);
        outerPanel.add(profileScrollPane, c01);
        outerPanel.add(hintLabel, c02);
        outerPanel.add(lowerButtonPanel, c03);

        add(outerPanel);
        pack();
        setLocationRelativeTo(BurpExtender.getBurp().getUiComponent());
    }

    public void addSelectedProfiles()
    {
        DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
        for (int i = 0; i < model.getRowCount(); i++) {
            if ((boolean)model.getValueAt(i, SELECT_COLUMN_INDEX)) {
                final String name = (String) model.getValueAt(i, NAME_COLUMN_INDEX);
                SigProfile profile = this.profileNameMap.get(name).sigProfile;
                burp.addProfile(profile);
                model.setValueAt(false, i, SELECT_COLUMN_INDEX);
            }
        }
    }

    private void updateImportTable(List<SigProfile> profiles, final String source)
    {
        // preserve selection status of current profiles.
        HashMap<String, Boolean> selectionMap =  new HashMap<>();
        DefaultTableModel model = (DefaultTableModel) this.profileTable.getModel();
        for (int i = 0; i < model.getRowCount(); i++) {
            final String name = (String) model.getValueAt(i, NAME_COLUMN_INDEX);
            selectionMap.put(name, (boolean) model.getValueAt(i, SELECT_COLUMN_INDEX));
        }
        model.setRowCount(0); // clear table

        for (SigProfile profile : profiles) {
            this.profileNameMap.put(profile.getName(), new NewSigProfile(profile, source));
            if (!selectionMap.containsKey(profile.getName())) {
                selectionMap.put(profile.getName(), true);
            }
        }

        // sort by name in table
        List<String> profileNames = new ArrayList<>(this.profileNameMap.keySet());
        Collections.sort(profileNames);

        for (final String name : profileNames) {
            NewSigProfile newProfile = this.profileNameMap.get(name);
            model.addRow(new Object[]{selectionMap.get(name), newProfile.sigProfile.getName(), newProfile.sigProfile.getAccessKeyIdForProfileSelection(), newProfile.source});
        }
    }

    private Path getAutoImportPath()
    {
        // favor path defined in environment. fallback to default path.
        final String envFile = System.getenv("AWS_SHARED_CREDENTIALS_FILE");
        if (envFile != null) {
            Path credPath = Paths.get(envFile);
            if (Files.exists(credPath)) {
                return credPath;
            }
        }

        Path credPath = Paths.get(System.getProperty("user.home"), ".aws", "credentials");
        if (Files.exists(credPath)) {
            return credPath;
        }
        return null;
    }

    private Path getChosenImportPath()
    {
        JFileChooser chooser = new JFileChooser(System.getProperty("user.home"));
        chooser.setFileHidingEnabled(false);
        if (chooser.showOpenDialog(burp.getUiComponent()) == JFileChooser.APPROVE_OPTION) {
            return Paths.get(chooser.getSelectedFile().getPath());
        }
        return null;
    }

    private void importProfilesFromFile(final Path credPath)
    {
        if (!Files.exists(credPath)) {
            burp.logger.error(String.format("Attempted to import credentials from non-existent file: %s", credPath));
        }
        List<SigProfile> profiles = SigProfile.fromCredentialPath(credPath);
        burp.logger.info(String.format("Importing %d credentials from: %s", profiles.size(), credPath));
        updateImportTable(profiles, credPath.toString());
    }

    private void importProfilesFromEnvironment()
    {
        // try to import creds from environment variables
        List<SigProfile> profiles = new ArrayList<>();
        SigProfile profile = SigProfile.fromEnvironment();
        if (profile != null) {
            profiles.add(profile);
        }
        updateImportTable(profiles, "**environment**");
    }

    private void importProfilesFromClipboard()
    {
        // try to import creds from the clipboard. format should be one env var per line, as used by the aws cli.
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        String text;
        try {
            text =  (String)clipboard.getData(DataFlavor.stringFlavor);
        } catch (IOException | UnsupportedFlavorException e) {
            return;
        }

        SigProfile profile = SigProfile.fromShellVars(text);
        if (profile != null) {
            updateImportTable(List.of(profile), "**clipboard**");
        }
    }
}
