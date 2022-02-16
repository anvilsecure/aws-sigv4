package burp;

import javax.swing.*;

/*
Provides a JTextArea styled like a JLabel which handles multiline text.
Text is not centered.

Reference: https://stackoverflow.com/questions/26420428/how-to-word-wrap-text-in-jlabel
 */
public class MultilineLabel extends JTextArea {
    private void init() {
        setWrapStyleWord(true);
        setLineWrap(true);
        setEditable(false);
        setFocusable(false);
        setBackground(UIManager.getColor("Label.background"));
        setFont(UIManager.getFont("Label.font"));
        setBorder(UIManager.getBorder("Label.border"));
        setColumns(35);
    }
    MultilineLabel(String text) {
        super(text);
        init();
    }
}
