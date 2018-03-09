package guis;


import main_program.EncryptionUtils;
import main_program.PasswodManager;
import main_program.User;
import java.awt.Color;
import java.awt.Image;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFrame;
import javax.swing.*;


public class Gui extends JFrame implements ActionListener {


    private JButton register;
    private JButton signIn;
    private JTextField username;
    private JPasswordField passwd;
    private JButton login;
    private JLabel usernameLabel;
    private JLabel passwdLabel;
    private JTextField usernameSign;
    private JPasswordField masterPasswd;
    private JTextField email;
    private JTextField name;
    private JTextField surname;
    private JButton ok;
    private JButton addPasswd;
    private JButton decryptPasswd;
    private JButton encryptPasswd;
    private JButton modifyPasswd;
    private JButton deletePasswd;
    private JButton ok2;
    private User user;
    private JPasswordField newPasswd;
    private JTextField domain;
    private final Image image = new ImageIcon(this.getClass().getResource("back.jpg")).getImage();
    private final JLabel info = new JLabel();

   
    public Gui() {
        initGui();
    }

    public void initGui() {
        
        this.setSize(360, 200);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setVisible(true);
        setLayout(null);
        setContentPane(new JLabel(new ImageIcon(image)));
        setResizable(false);

        register = new JButton("Register");
        signIn = new JButton("Sign In");
        login = new JButton("Login");
        username = new JTextField();
        passwd = new JPasswordField();
        usernameLabel = new JLabel("Username:");
        passwdLabel = new JLabel("Password:");
        usernameSign = new JTextField();
        email = new JTextField();
        masterPasswd = new JPasswordField();
        name = new JTextField();
        surname = new JTextField();
        ok = new JButton("ok");
        addPasswd = new JButton("Add Password");
        decryptPasswd = new JButton("decrypt");
        encryptPasswd = new JButton("encrypt");
        modifyPasswd = new JButton("change");
        deletePasswd = new JButton("delete");
        newPasswd = new JPasswordField();
        domain = new JTextField();
        ok2 = new JButton("ok2");

            
        this.add(register);
        this.add(signIn);
        this.add(login);
        this.add(username);
        this.add(passwd);
        this.add(passwdLabel);
        this.add(usernameLabel);
        this.add(email);
        this.add(usernameSign);
        this.add(masterPasswd);
        this.add(name);
        this.add(surname);
        this.add(ok);
        this.add(addPasswd);
        this.add(decryptPasswd);
        this.add(encryptPasswd);
        this.add(modifyPasswd);
        this.add(deletePasswd);
        this.add(newPasswd);
        this.add(domain);
        this.add(ok2);
        this.add(info);

        register.setVisible(true);
        signIn.setVisible(true);
        login.setVisible(false);
        username.setVisible(false);
        passwd.setVisible(false);
        usernameLabel.setVisible(false);
        passwdLabel.setVisible(false);
        email.setVisible(false);
        usernameSign.setVisible(false);
        masterPasswd.setVisible(false);
        name.setVisible(false);
        surname.setVisible(false);
        ok.setVisible(false);
        addPasswd.setVisible(false);
        decryptPasswd.setVisible(false);
        encryptPasswd.setVisible(false);
        modifyPasswd.setVisible(false);
        deletePasswd.setVisible(false);
        newPasswd.setVisible(false);
        domain.setVisible(false);
        info.setVisible(false);

        ok2.setVisible(false);

        email.setText("email");
        usernameSign.setText("username");
        domain.setText("domain");
        newPasswd.setText("password");
        masterPasswd.setText("master password");
        name.setText("name");
        surname.setText("surename");
        register.setBounds(65, 48, 100, 60);
        signIn.setBounds(185, 48, 100, 60);
        login.setBounds(185, 48, 100, 60);
        username.setBounds(80, 48, 100, 30);
        passwd.setBounds(80, 80, 100, 30);
        usernameLabel.setBounds(0, 45, 90, 30);
        passwdLabel.setBounds(0, 77, 90, 30);
        email.setBounds(80, 15, 100, 30);
        usernameSign.setBounds(80, 45, 100, 30);
        masterPasswd.setBounds(80, 75, 100, 30);
        name.setBounds(80, 105, 100, 30);
        surname.setBounds(80, 135, 100, 30);
        ok.setBounds(185, 48, 165, 60);
        addPasswd.setBounds(80, 15, 100, 30);
        encryptPasswd.setBounds(80, 45, 100, 30);
        decryptPasswd.setBounds(80, 75, 100, 30);
        modifyPasswd.setBounds(80, 105, 100, 30);
        deletePasswd.setBounds(80, 135, 100, 30);
        newPasswd.setBounds(200, 46, 100, 30);
        domain.setBounds(200, 76, 100, 30);
        ok2.setBounds(300, 58, 80, 50);
        info.setBounds(250, 80, 100, 100);
        info.setBackground(Color.yellow);

        register.setBackground(Color.YELLOW);
        signIn.setBackground(Color.YELLOW);
        login.setBackground(Color.YELLOW);
        passwd.setBackground(Color.YELLOW);
        username.setBackground(Color.YELLOW);
        ok.setBackground(Color.YELLOW);
        newPasswd.setBackground(Color.YELLOW);
        domain.setBackground(Color.YELLOW);
        ok2.setBackground(Color.YELLOW);

        login.addActionListener(this);
        signIn.addActionListener(this);
        register.addActionListener(this);
        ok.addActionListener(this);
        addPasswd.addActionListener(this);
        ok2.addActionListener(this);
        this.decryptPasswd.addActionListener(this);
        this.encryptPasswd.addActionListener(this);
        this.modifyPasswd.addActionListener(this);
        this.deletePasswd.addActionListener(this);

        newPasswd.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent evt) {
                newPasswd.setText("");
            }
        });
        domain.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent evt) {
                domain.setText("");
            }
        });
        email.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent evt) {
                email.setText("");
            }
        });
        name.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent evt) {
                name.setText("");
            }
        });
        username.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent evt) {
                username.setText("");
            }
        });
        surname.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent evt) {
                surname.setText("");
            }
        });
        masterPasswd.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent evt) {
                masterPasswd.setText("");
            }
        });
        username.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent evt) {
                username.setText("");
            }
        });
        passwd.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent evt) {
                passwd.setText("");
            }
        });

    }

    public void initResgisterForm() {
        //εμφάνιση των καταλληλων component για την φόρμα εγγραφής
        register.setVisible(false);
        signIn.setVisible(false);
        email.setVisible(true);
        usernameSign.setVisible(true);
        masterPasswd.setVisible(true);
        name.setVisible(true);
        surname.setVisible(true);
        ok.setVisible(true);

    }

    public void initSignInForm() {
        //init login form
        register.setVisible(false);
        signIn.setVisible(false);
        usernameSign.setVisible(false);
        masterPasswd.setVisible(false);
        email.setVisible(false);
        name.setVisible(false);
        surname.setVisible(false);
        ok.setVisible(false);
        username.setVisible(true);
        passwd.setVisible(true);
        login.setVisible(true);
        passwdLabel.setVisible(true);
        usernameLabel.setVisible(true);

    }

    public void initMainAppFrame() {
        //init main menu after login 
        addPasswd.setVisible(true);
        decryptPasswd.setVisible(true);
        encryptPasswd.setVisible(true);
        modifyPasswd.setVisible(true);
        deletePasswd.setVisible(true);
        username.setVisible(false);
        passwd.setVisible(false);
        login.setVisible(false);
        passwdLabel.setVisible(false);
        usernameLabel.setVisible(false);
        info.setVisible(true);
    }

    @Override
    public void actionPerformed(ActionEvent ae) {
        if (ae.getSource().equals(signIn)) {
            initSignInForm();

        }
        if (ae.getSource().equals(register)) {
            initResgisterForm();

        }
        if (ae.getSource().equals(login)) {

            try {
                if (PasswodManager.checkHash(username.getText(), passwd.getText())) {
                    user = new User(username.getText(), passwd.getText(), EncryptionUtils.getsKey(passwd.getText(), username.getText()));
                    initMainAppFrame();
                } else {
                    System.out.println("FAIL");
                }
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        if (ae.getSource().equals(ok)) {

            try {
                User user = new User(name.getText(), surname.getText(), usernameSign.getText(), email.getText(), masterPasswd.getText());
                PasswodManager.createAcc(user);
                initSignInForm();
            } catch (Exception ex) {
                Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
            }
           
        }
        if (ae.getSource().equals(addPasswd)) {
            newPasswd.setVisible(true);
            domain.setVisible(true);
            ok2.setVisible(true);

        }
        if (ae.getSource().equals(ok2)) {
            try {
                PasswodManager.newPasswd(newPasswd.getText(), user, domain.getText());
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        if (ae.getSource().equals(this.encryptPasswd)) {

            domain.setVisible(true);
            ok2.setVisible(true);

        }
        if (ae.getSource().equals(this.decryptPasswd)) {

            domain.setVisible(true);
            ok2.setVisible(true);
            try {
                info.setText(PasswodManager.decryptPasswd(domain.getText(), user));
            } catch (IOException ex) {
                Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        if (ae.getSource().equals(this.deletePasswd)) {

            domain.setVisible(true);
            ok2.setVisible(true);
            try {
                PasswodManager.deletePasswd(domain.getText(), user);
            } catch (IOException ex) {
                Logger.getLogger(Gui.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        if (ae.getSource().equals(this.modifyPasswd)) {

            domain.setVisible(true);
            ok2.setVisible(true);

        }

    }

}
