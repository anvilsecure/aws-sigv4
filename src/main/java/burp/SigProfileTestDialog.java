package burp;

import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

import javax.swing.*;
import java.awt.*;


public class SigProfileTestDialog extends JDialog
{
    public SigProfileTestDialog(Frame owner, final SigProfile profile, boolean modal, final GetCallerIdentityResponse response)
    {
        super(owner, profile.getName(), modal);

        Object[][] data = {
                {"Profile", profile.getName()},
                {"AccountId", response.account()},
                {"Arn", response.arn()},
                {"UserId", response.userId()}
        };
        JTable resultTable = new JTable(data, new String[]{"key", "value"}) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        resultTable.getColumnModel().getColumn(0).setPreferredWidth(100);
        resultTable.getColumnModel().getColumn(1).setPreferredWidth(450);
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(resultTable, BorderLayout.CENTER);

        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(actionEvent -> {
            setVisible(false);
            dispose();
        });
        contentPanel.add(closeButton, BorderLayout.PAGE_END);

        // not necessary but adds a nice border
        JScrollPane outerScrollPane = new JScrollPane(contentPanel);
        add(outerScrollPane);
        pack();
        setLocationRelativeTo(SwingUtilities.getWindowAncestor(BurpExtender.getBurp().getUiComponent()));
    }
}
