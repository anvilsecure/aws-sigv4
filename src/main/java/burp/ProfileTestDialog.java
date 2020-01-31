package burp;

import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

import javax.swing.*;
import java.awt.*;

public class ProfileTestDialog extends JDialog
{
    private String encode(final String label)
    {
        return label.replace("<", "&lt;").replace(">", "&gt;");
    }

    public ProfileTestDialog(Frame owner, final AWSProfile profile, boolean modal, final GetCallerIdentityResponse response)
    {
        super(owner, profile.getName(), modal);

        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.PAGE_AXIS));

        contentPanel.add(new JLabel(String.format("<html><b>Profile:</b>&nbsp;%s</html>", encode(profile.getName()))));
        contentPanel.add(new JLabel(String.format("<html><b>AccountId:</b>&nbsp;%s</html>", encode(response.account()))));
        contentPanel.add(new JLabel(String.format("<html><b>Arn:</b>&nbsp;%s</html>", encode(response.arn()))));
        contentPanel.add(new JLabel(String.format("<html><b>UserId:</b>&nbsp;%s</html>", encode(response.userId()))));

        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(actionEvent -> {
            setVisible(false);
            dispose();
        });
        contentPanel.add(closeButton);

        JScrollPane outerScrollPane = new JScrollPane(contentPanel);
        add(outerScrollPane);
        pack();
        setLocationRelativeTo(SwingUtilities.getWindowAncestor(BurpExtender.getBurp().getUiComponent()));
    }
}
