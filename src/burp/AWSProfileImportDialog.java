package burp;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

class NewAWSProfile
{
    public String source;
    public AWSProfile awsProfile;

    public NewAWSProfile(AWSProfile awsProfile, String source)
    {
        this.awsProfile = awsProfile;
        this.source = source;
    }
}

public class AWSProfileImportDialog extends JDialog
{
    private BurpExtender burp;
    private JTable profileTable;
    private HashMap<String, NewAWSProfile> profileNameMap;
    private static int SELECT_COLUMN_INDEX = 0;
    private static int NAME_COLUMN_INDEX = 1;
    private static int KEYID_COLUMN_INDEX = 2;

    public AWSProfileImportDialog(Frame owner, String title, boolean modal, BurpExtender burp)
    {
        super(owner, title, modal);
        this.burp = burp;
        this.profileNameMap = new HashMap<>();
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        JPanel outerPanel = new JPanel(new GridBagLayout());

        // import from file buttons
        JPanel importButtonPanel = new JPanel();
        TitledBorder importBorder= new TitledBorder("Source");
        importBorder.setTitleColor(BurpExtender.textOrange);
        importButtonPanel.setBorder(importBorder);
        JButton autoImportButton = new JButton("Auto");
        JButton chooseImportButton = new JButton("File");
        JButton envImportButton = new JButton("Env");
        importButtonPanel.add(autoImportButton);
        importButtonPanel.add(chooseImportButton);
        importButtonPanel.add(envImportButton);

        autoImportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                importProfilesFromFile(getAutoImportPath());
                importProfilesFromEnvironment();
            }
        });

        chooseImportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                importProfilesFromFile(getChosenImportPath());
            }
        });

        envImportButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                importProfilesFromEnvironment();
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
        profileTable.getColumnModel().getColumn(KEYID_COLUMN_INDEX).setMinWidth(150);
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
                addSelectedProfiles();
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
        c00.gridwidth = 2;
        GridBagConstraints c01 = new GridBagConstraints();
        c01.gridy = 1;
        c01.gridwidth = 1;
        GridBagConstraints c02 = new GridBagConstraints();
        c02.anchor = GridBagConstraints.FIRST_LINE_START;
        c02.gridy = 2;
        c02.gridwidth = 1;
        outerPanel.add(topButtonPanel, c00);
        outerPanel.add(profileScrollPane, c01);
        outerPanel.add(lowerButtonPanel, c02);

        add(outerPanel);
        pack();
        setLocationRelativeTo(burp.outerFrame);
    }

    public void addSelectedProfiles()
    {
        DefaultTableModel model = (DefaultTableModel) profileTable.getModel();
        for (int i = 0; i < model.getRowCount(); i++) {
            if ((boolean)model.getValueAt(i, SELECT_COLUMN_INDEX)) {
                final String name = (String) model.getValueAt(i, NAME_COLUMN_INDEX);
                AWSProfile profile = this.profileNameMap.get(name).awsProfile;
                burp.addProfile(profile);
            }
        }
    }

    private void updateImportTable(ArrayList<AWSProfile> profiles, final String source)
    {
        for (AWSProfile profile : profiles) {
            this.profileNameMap.put(profile.name, new NewAWSProfile(profile, source));
        }
        DefaultTableModel model = (DefaultTableModel) this.profileTable.getModel();
        model.setRowCount(0); // clear table

        // sort by name in table
        List<String> profileNames = new ArrayList<>(this.profileNameMap.keySet());
        Collections.sort(profileNames);

        for (final String name : profileNames) {
            NewAWSProfile newProfile = this.profileNameMap.get(name);
            model.addRow(new Object[]{true, newProfile.awsProfile.name, newProfile.awsProfile.accessKeyId, newProfile.source});
        }
    }

    private Path getAutoImportPath()
    {
        Path credPath = Paths.get(System.getProperty("user.home"), ".aws", "credentials");
        if (!Files.exists(credPath)) {
            credPath = null;
        }
        return credPath;
    }

    private Path getChosenImportPath()
    {
        JFileChooser chooser = new JFileChooser(System.getProperty("user.home"));
        chooser.setFileHidingEnabled(false);
        if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
            return Paths.get(chooser.getSelectedFile().getPath());
        }
        return null;
    }

    private void importProfilesFromFile(final Path credPath)
    {
        if (!Files.exists(credPath)) {
            burp.logger.error(String.format("Attempted to import credentials from non-existent file: %s", credPath));
        }
        ArrayList<AWSProfile> profiles = AWSProfile.fromCredentialPath(credPath);
        burp.logger.info(String.format("Importing %d credentials from: %s", profiles.size(), credPath));
        updateImportTable(profiles, credPath.toString());
    }

    private void importProfilesFromEnvironment()
    {
        // try to import creds from environment variables
        ArrayList<AWSProfile> profiles = new ArrayList<>();
        AWSProfile profile = AWSProfile.fromEnvironment();
        if (profile != null) {
            profiles.add(profile);
        }
        updateImportTable(profiles, "<html><i>environment</i></html>");
    }
}
