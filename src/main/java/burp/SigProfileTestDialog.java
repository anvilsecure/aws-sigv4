package burp;

import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

import javax.swing.*;
import java.awt.*;


public class SigProfileTestDialog extends JDialog
{
    private final static int NAME_COLUMN = 0;
    private final static int VALUE_COLUMN = 1;
    private final static int PROFILE_ROW = 0;
    private final static int ACCOUNT_ID_ROW = 1;
    private final static int ARN_ROW = 2;
    private final static int USER_ID_ROW = 3;
    private JTable resultTable;

    private void init(final SigProfile profile) {
        Object[][] data = {
                {"Profile", profile.getName()},
                {"AccountId", "..."},
                {"Arn", "..."},
                {"UserId", "..."}
        };
        resultTable = new JTable(data, new String[]{"key", "value"}) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        resultTable.getColumnModel().getColumn(NAME_COLUMN).setPreferredWidth(100);
        resultTable.getColumnModel().getColumn(VALUE_COLUMN).setPreferredWidth(450);
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

    public SigProfileTestDialog(Frame owner, final SigProfile profile, boolean modal) {
        super(owner, profile.getName(), modal);
        init(profile);
    }

    public SigProfileTestDialog(Frame owner, final SigProfile profile, boolean modal, final GetCallerIdentityResponse response) {
        super(owner, profile.getName(), modal);
        init(profile);
        updateWithResult(response);
    }

    public void updateWithResult(final GetCallerIdentityResponse response) {
        resultTable.setValueAt(response.account(), ACCOUNT_ID_ROW, VALUE_COLUMN);
        resultTable.setValueAt(response.arn(), ARN_ROW, VALUE_COLUMN);
        resultTable.setValueAt(response.userId(), USER_ID_ROW, VALUE_COLUMN);
        pack();
    }
}
