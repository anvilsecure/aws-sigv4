package burp;

import javax.swing.*;

/*
Provides a JTextArea styled like a JLabel which handles multiline text.
Text is not centered.
 */
public class MultilineLabel extends JTextArea {
    private void init() {
        setWrapStyleWord(true);
        setLineWrap(true);
        setEditable(false);
        setFocusable(false);
        setBackground(UIManager.getColor("Label.background"));
        setFont(UIManager.getFont("Label.font"));
        setBorder(UIManager.getBorder("Label.font"));
        setColumns(35);
    }
    MultilineLabel(String text) {
        super(text);
        init();
    }
}
