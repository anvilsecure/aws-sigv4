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
        /*
        ,-outerPanel---------
        |    textPanel
        |    bottomPanel
        '--------------------
         */
        JPanel outerPanel = new JPanel(new GridLayout(2, 1));
        outerPanel.setBorder(new TitledBorder(""));
        JDialog dialog = new JDialog(burp.outerFrame, "Add Profile", true);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        JPanel textPanel = new JPanel(new GridBagLayout());

        textPanel.add(new JLabel("Name"), newConstraint(0, 0, GridBagConstraints.FIRST_LINE_START));
        JTextField nameTextField = new JTextField("", 40);
        textPanel.add(nameTextField, newConstraint(1, 0));
        textPanel.add(new JLabel("KeyId"), newConstraint(0, 1, GridBagConstraints.FIRST_LINE_START));
        JTextField keyIdTextField = new JTextField("", 40);
        textPanel.add(keyIdTextField, newConstraint(1, 1));
        textPanel.add(new JLabel("SecretKey"), newConstraint(0, 2, GridBagConstraints.FIRST_LINE_START));
        JTextField secretKeyTextField = new JTextField("", 40);
        textPanel.add(secretKeyTextField, newConstraint(1, 2));
        textPanel.add(new JLabel("Region"), newConstraint(0, 3, GridBagConstraints.FIRST_LINE_START));
        JTextField regionTextField = new JTextField("", 40);
        textPanel.add(regionTextField, newConstraint(1, 3));
        textPanel.add(new JLabel("Service"), newConstraint(0, 4, GridBagConstraints.FIRST_LINE_START));
        JTextField serviceTextField = new JTextField("", 40);
        textPanel.add(serviceTextField, newConstraint(1, 4));
        outerPanel.add(textPanel);

        JPanel bottomPanel = new JPanel(new GridBagLayout());
        JLabel statusLabel = new JLabel("Ok to submit");
        JButton okButton = new JButton("Ok");
        JButton cancelButton = new JButton("Cancel");
        bottomPanel.add(statusLabel, newConstraint(0, 0, 2, 1));
        bottomPanel.add(okButton, newConstraint(0, 1));
        bottomPanel.add(cancelButton, newConstraint(1, 1));
        outerPanel.add(bottomPanel);

        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                dialog.setVisible(false);
            }
        });
        okButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                if (burp.addProfile(new AWSProfile(nameTextField.getText(), keyIdTextField.getText(), secretKeyTextField.getText(),
                        regionTextField.getText(), true, serviceTextField.getText(), true))) {
                    dialog.setVisible(false);
                } else {
                    statusLabel.setText("Invalid settings");
                }
            }
        });

        if (profile != null) {
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
