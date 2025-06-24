package com.example.vulnapp;

import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.servlet.http.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.logging.Logger;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * VulnApp.java - Intentionally Vulnerable Java Application for SAST Testing
 * This code contains multiple security vulnerabilities for testing with Semgrep
 * DO NOT USE IN PRODUCTION - FOR TESTING PURPOSES ONLY
 */
public class VulnApp {
    
    private static final Logger logger = Logger.getLogger(VulnApp.class.getName());
    private Connection dbConnection;
    
    // 1. SQL Injection Vulnerability
    public List<User> getUserById(String userId) throws SQLException {
        String query = "SELECT * FROM users WHERE id = " + userId; // Direct concatenation
        Statement stmt = dbConnection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        List<User> users = new ArrayList<>();
        
        while (rs.next()) {
            users.add(new User(rs.getString("name"), rs.getString("email")));
        }
        return users;
    }
    
    // 2. Command Injection Vulnerability
    public String executeCommand(String userInput) throws IOException {
        String command = "ping -c 1 " + userInput; // Direct command injection
        Process process = Runtime.getRuntime().exec(command);
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }
    
    // 3. Path Traversal Vulnerability
    public String readFile(String filename) throws IOException {
        String filePath = "/app/files/" + filename; // No path validation
        return new String(Files.readAllBytes(Paths.get(filePath)));
    }
    
    // 4. XSS Vulnerability (Servlet)
    public void displayUserData(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        String userData = request.getParameter("data");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("User data: " + userData); // Direct output without escaping
        out.println("</body></html>");
    }
    
    // 5. Hardcoded Credentials
    private static final String DB_PASSWORD = "admin123"; // Hardcoded password
    private static final String API_KEY = "sk-1234567890abcdef"; // Hardcoded API key
    
    public Connection getDatabaseConnection() throws SQLException {
        String url = "jdbc:mysql://localhost:3306/mydb";
        String username = "root";
        return DriverManager.getConnection(url, username, DB_PASSWORD);
    }
    
    // 6. Weak Cryptography
    public String encryptData(String data) throws Exception {
        String key = "1234567890123456"; // Weak, hardcoded key
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES"); // ECB mode - insecure
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    // 7. Insecure Random Number Generation
    public String generateToken() {
        Random random = new Random(); // Not cryptographically secure
        return String.valueOf(random.nextLong());
    }
    
    // 8. MD5 Hash Usage (Weak Hashing)
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // Weak algorithm
        byte[] hash = md.digest(password.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
    
    // 9. LDAP Injection Vulnerability
    public String searchLDAP(String username) {
        String filter = "(uid=" + username + ")"; // LDAP injection possible
        // LDAP search code would go here
        return "cn=user,ou=people,dc=example,dc=com";
    }
    
    // 10. Deserialization Vulnerability
    public Object deserializeObject(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject(); // Unsafe deserialization
    }
    
    // 11. Information Disclosure in Exception Handling
    public void processUserLogin(String username, String password) {
        try {
            // Login logic here
            authenticateUser(username, password);
        } catch (SQLException e) {
            logger.severe("Database error: " + e.getMessage()); // Leaks internal info
            throw new RuntimeException("Login failed: " + e.getMessage()); // Exposes stack trace
        }
    }
    
    // 12. SSRF (Server-Side Request Forgery)
    public String fetchUrl(String url) throws IOException {
        URL targetUrl = new URL(url); // No URL validation
        HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        return response.toString();
    }
    
    // 13. XXE (XML External Entity) Vulnerability
    public void parseXML(String xmlData) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // XXE vulnerability - external entities not disabled
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xmlData.getBytes()));
        // Process document...
    }
    
    // 14. Regex DoS (ReDoS)
    public boolean validateEmail(String email) {
        String regex = "^([a-zA-Z0-9])+([a-zA-Z0-9\\._-])*@([a-zA-Z0-9_-])+([a-zA-Z0-9\\._-]+)+$";
        return email.matches(regex); // Vulnerable to ReDoS
    }
    
    // 15. Race Condition
    private static int counter = 0;
    
    public void incrementCounter() {
        counter++; // Not thread-safe, race condition possible
    }
    
    // 16. Improper Certificate Validation
    public void makeHttpsRequest(String url) throws Exception {
        // Disable certificate validation (dangerous)
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        
        URL targetUrl = new URL(url);
        HttpsURLConnection connection = (HttpsURLConnection) targetUrl.openConnection();
        // Make request...
    }
    
    // Helper method for SQL injection example
    private void authenticateUser(String username, String password) throws SQLException {
        String query = "SELECT * FROM users WHERE username='" + username + 
                      "' AND password='" + password + "'"; // SQL injection
        Statement stmt = dbConnection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
    }
    
    // User class for demonstration
    public static class User {
        private String name;
        private String email;
        
        public User(String name, String email) {
            this.name = name;
            this.email = email;
        }
        
        // Getters and setters...
        public String getName() { return name; }
        public String getEmail() { return email; }
    }
    
    public static void main(String[] args) {
        System.out.println("VulnApp - Vulnerable Java Application for SAST Testing");
        System.out.println("This application contains intentional security vulnerabilities");
        System.out.println("DO NOT USE IN PRODUCTION ENVIRONMENTS");
    }
}
