package gui;

import javax.swing.*;
import java.awt.*;

import static javax.swing.JFrame.EXIT_ON_CLOSE;

public class PeFrame{

    public PeFrame() {
        JFrame frame = new JFrame();
        frame.setTitle("Test");
        frame.setSize(640, 480);

        frame.setContentPane(new test().getPanel1());
        frame.setDefaultCloseOperation(EXIT_ON_CLOSE);
        frame.setVisible(true);
    }
}
