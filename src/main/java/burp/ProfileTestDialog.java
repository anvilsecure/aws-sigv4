package burp;

import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class ProfileTestDialog extends JDialog
{
    public ProfileTestDialog(Frame owner, String title, boolean modal, GetCallerIdentityResponse response)
    {
        super(owner, title, modal);

        JPanel outerPanel = new JPanel();
        outerPanel.setLayout(new BoxLayout(outerPanel, BoxLayout.PAGE_AXIS));

        outerPanel.add(new JLabel(String.format("<html><b>AccountId:</b> %s</html>", response.account())));
        outerPanel.add(new JLabel(String.format("<html><b>Arn:</b> %s</html>", response.arn())));
        outerPanel.add(new JLabel(String.format("<html><b>UserId:</b> %s</html>", response.userId())));

        JButton closeButton = new JButton("close");
        closeButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent actionEvent)
            {
                setVisible(false);
                dispose();
            }
        });
        outerPanel.add(closeButton);

        add(outerPanel);
        pack();
        setLocationRelativeTo(SwingUtilities.getWindowAncestor(BurpExtender.getBurp().getUiComponent()));
    }
}
