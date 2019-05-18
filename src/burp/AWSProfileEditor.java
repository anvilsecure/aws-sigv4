package burp;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class AWSProfileEditor {

    private static GridBagConstraints newConstraint(int gridx, int gridy, int gridwidth, int gridheight) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridy = gridy;
        c.gridx = gridx;
        c.gridwidth = gridwidth;
        c.gridheight = gridheight;
        return c;
    }

    private static GridBagConstraints newConstraint(int gridx, int gridy, int anchor) {
        GridBagConstraints c = newConstraint(gridx, gridy, 1, 1);
        c.anchor = anchor;
        return c;
    }

    private static GridBagConstraints newConstraint(int gridx, int gridy) {
        return newConstraint(gridx, gridy, 1, 1);
    }

    /*
    return a dialog with a form for editing profiles. optional profile param can be used to populate the form.
    set profile to null for a create form.
     */
    public static JDialog getAddProfileDialog(BurpExtender burp, AWSProfile profile) {

        JDialog dialog = new JDialog(burp.outerFrame, "Add/Edit Profile", true);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        JPanel outerPanel = new JPanel(new GridBagLayout());
        outerPanel.setBorder(new TitledBorder(""));

        outerPanel.add(new JLabel("Name"), newConstraint(0, 0, GridBagConstraints.FIRST_LINE_START));
        JTextField nameTextField = new JTextField("", 40);
        outerPanel.add(nameTextField, newConstraint(1, 0));
        outerPanel.add(new JLabel("KeyId"), newConstraint(0, 1, GridBagConstraints.FIRST_LINE_START));
        JTextField keyIdTextField = new JTextField("", 40);
        outerPanel.add(keyIdTextField, newConstraint(1, 1));
        outerPanel.add(new JLabel("SecretKey"), newConstraint(0, 2, GridBagConstraints.FIRST_LINE_START));
        JTextField secretKeyTextField = new JTextField("", 40);
        outerPanel.add(secretKeyTextField, newConstraint(1, 2));
        outerPanel.add(new JLabel("Region"), newConstraint(0, 3, GridBagConstraints.FIRST_LINE_START));
        JTextField regionTextField = new JTextField("", 40);
        outerPanel.add(regionTextField, newConstraint(1, 3));
        outerPanel.add(new JLabel("Service"), newConstraint(0, 4, GridBagConstraints.FIRST_LINE_START));
        JTextField serviceTextField = new JTextField("", 40);
        outerPanel.add(serviceTextField, newConstraint(1, 4));

        JLabel statusLabel = new JLabel("Ok to submit");
        statusLabel.setForeground(burp.textOrange);
        JButton okButton = new JButton("Ok");
        JButton cancelButton = new JButton("Cancel");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        outerPanel.add(statusLabel, newConstraint(0, 5, 2, 1));
        outerPanel.add(buttonPanel, newConstraint(0, 6, 2, 1));

        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                dialog.setVisible(false);
            }
        });
        okButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                if (burp.updateProfile(profile, new AWSProfile(nameTextField.getText(), keyIdTextField.getText(), secretKeyTextField.getText(),
                        regionTextField.getText(),  serviceTextField.getText()))) {
                    dialog.setVisible(false);
                }
                else {
                    statusLabel.setText("Invalid settings. Ensure keyId is unique and name is not empty.");
                }
            }
        });

        if (profile != null) {
            // populate fields with existing profile for an "edit" dialog.
            nameTextField.setText(profile.name);
            keyIdTextField.setText(profile.accessKeyId);
            secretKeyTextField.setText(profile.secretKey);
            regionTextField.setText(profile.region);
            serviceTextField.setText(profile.service);
        }

        dialog.add(outerPanel);
        dialog.pack();
        dialog.setLocationRelativeTo(burp.outerFrame);
        return dialog;
    }
}
