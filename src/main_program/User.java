package main_program;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class User {

    private String name;
    private String surname;
    private String username;
    private String email;
    private String mastePasswd;
    private Path path;

   
    private byte[] salt;

    public User(String name, String surname, String username, String email, String masterPasswd) throws IOException {
        this.name = name;
        this.surname = surname;
        this.username = username;
        this.email = email;
        this.mastePasswd = masterPasswd;

        path = Paths.get("Users/" + username);
        Files.createDirectories(path);

    }

    public User(String username, String passwd, byte[] salt) {
        this.username = username;
        this.mastePasswd = passwd;
        this.salt = salt;
    }

    protected String getName() {
        return name;
    }

    protected byte[] getSalt() {
        return salt;
    }

    protected void setName(String name) {
        this.name = name;
    }

    protected String getSurname() {
        return surname;
    }

    protected void setSurname(String surname) {
        this.surname = surname;
    }

    protected String getUsername() {
        return username;
    }

    protected void setUsername(String username) {
        this.username = username;
    }

    protected String getEmail() {
        return email;
    }

    protected void setEmail(String email) {
        this.email = email;
    }

    protected String getMastePasswd() {
        return mastePasswd;
    }

    protected void setMastePasswd(String mastePasswd) {
        this.mastePasswd = mastePasswd;
    }
     public Path getPath() {
        return path;
    }

    public void setPath(Path path) {
        this.path = path;
    }

}
