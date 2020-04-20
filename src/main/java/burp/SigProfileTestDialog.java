package burp;

import org.apache.commons.text.StringEscapeUtils;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

import javax.swing.*;
import java.awt.*;

public class SigProfileTestDialog extends JDialog
{
    public SigProfileTestDialog(Frame owner, final SigProfile profile, boolean modal, final GetCallerIdentityResponse response)
    {
        super(owner, profile.getName(), modal);

        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.PAGE_AXIS));
        contentPanel.add(new JLabel(String.format("<html><b>Profile:</b>&nbsp;%s</html>", StringEscapeUtils.escapeHtml4(profile.getName()))));
        contentPanel.add(new JLabel(String.format("<html><b>AccountId:</b>&nbsp;%s</html>", StringEscapeUtils.escapeHtml4(response.account()))));
        contentPanel.add(new JLabel(String.format("<html><b>Arn:</b>&nbsp;%s</html>", StringEscapeUtils.escapeHtml4(response.arn()))));
        contentPanel.add(new JLabel(String.format("<html><b>UserId:</b>&nbsp;%s</html>", StringEscapeUtils.escapeHtml4(response.userId()))));

        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(actionEvent -> {
            setVisible(false);
            dispose();
        });
        contentPanel.add(closeButton);

        // not necessary but adds a nice border
        JScrollPane outerScrollPane = new JScrollPane(contentPanel);
        add(outerScrollPane);
        pack();
        setLocationRelativeTo(SwingUtilities.getWindowAncestor(BurpExtender.getBurp().getUiComponent()));
    }
}
