package burp;

import javax.swing.*;
import java.util.List;

/*
right-click context menu for selecting profiles
 */
public class AWSContextMenu implements IContextMenuFactory
{
    private BurpExtender burpExtender;

    public AWSContextMenu(BurpExtender burpExtender)
    {
        this.burpExtender = burpExtender;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
       return this.burpExtender.getContextMenuItems();
    }
}
