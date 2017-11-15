package PassMan;

//Θελούρας Κωνσταντίνος Παναγιώτης
//icsd12058

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

    public String getName() {
        return name;
    }

    public byte[] getSalt() {
        return salt;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getMastePasswd() {
        return mastePasswd;
    }

    public void setMastePasswd(String mastePasswd) {
        this.mastePasswd = mastePasswd;
    }

}
