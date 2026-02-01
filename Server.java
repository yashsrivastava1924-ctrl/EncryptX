import java.awt.*;
import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.SecretKey;
import javax.swing.*;

public class Server extends JFrame {
    private final JTextField portField = new JTextField("8080", 6);
    private final JButton startBtn = new JButton("Start Server");
    private final JLabel statusLabel = new JLabel("Stopped");
    private final JTextArea logArea = new JTextArea(10, 40);
    private final JButton decryptBtn = new JButton("Decrypt File");

    // networking
    private ServerSocket serverSocket;
    private volatile boolean running = false;
    private final ExecutorService pool = Executors.newCachedThreadPool();

    // crypto state for optional manual decrypt (kept in memory while server runs)
    private KeyPair rsaPair;
    private volatile byte[] lastEncryptedBytes;
    private volatile byte[] lastAesKeyBytes;
    private volatile byte[] lastIv;
    private volatile String lastFilename;

    public Server() {
        super("Secure File Transfer - Server");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();

        // top row: start button + port + status
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));
        top.add(startBtn);
        top.add(new JLabel("Port"));
        top.add(portField);
        top.add(new JLabel("Status"));
        top.add(statusLabel);

        c.gridx = 0; c.gridy = 0; c.gridwidth = 1;
        add(top, c);

        // log area
        logArea.setEditable(false);
        JScrollPane sp = new JScrollPane(logArea);
        sp.setPreferredSize(new Dimension(520, 220));
        c.gridx = 0; c.gridy = 1; c.insets = new Insets(10,0,0,0);
        add(sp, c);

        // decrypt button
        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bottom.add(decryptBtn);
        c.gridx = 0; c.gridy = 2; c.insets = new Insets(6,0,0,0);
        add(bottom, c);

        startBtn.addActionListener(e -> toggleServer());
        decryptBtn.addActionListener(e -> manualDecrypt());
        decryptBtn.setEnabled(false);

        pack();
        setLocationRelativeTo(null);
    }

    private void toggleServer() {
        if (!running) {
            int port = Integer.parseInt(portField.getText().trim());
            startServer(port);
        } else {
            stopServer();
        }
    }

    private void startServer(int port) {
        try {
            rsaPair = CryptoUtils.generateRSAKeyPair();
            appendLog("RSA keypair generated (public " + rsaPair.getPublic().getEncoded().length + " bytes)");
            serverSocket = new ServerSocket(port);
            running = true;
            startBtn.setText("Stop Server");
            statusLabel.setText("Listening");
            appendLog("Server listening on port " + port);
            decryptBtn.setEnabled(false);

            pool.submit(() -> {
                while (running) {
                    try {
                        Socket client = serverSocket.accept();
                        appendLog("Connection: " + client.getRemoteSocketAddress());
                        pool.submit(() -> handleClient(client));
                    } catch (IOException ex) {
                        if (running) appendLog("Accept error: " + ex.getMessage());
                    }
                }
            });
        } catch (Exception ex) {
            appendLog("Start server error: " + ex.getMessage());
        }
    }

    private void stopServer() {
        running = false;
        try {
            if (serverSocket != null) serverSocket.close();
            appendLog("Server stopped.");
            startBtn.setText("Start Server");
            statusLabel.setText("Stopped");
        } catch (IOException ex) {
            appendLog("Stop error: " + ex.getMessage());
        }
    }

    private void handleClient(Socket s) {
        try (DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
             DataInputStream dis = new DataInputStream(new BufferedInputStream(s.getInputStream()))) {

            // 1) send public key
            byte[] pub = CryptoUtils.publicKeyToBytes(rsaPair.getPublic());
            dos.writeInt(pub.length);
            dos.write(pub);
            dos.flush();
            appendLog("Sent public key to client.");

            // 2) receive wrapped key
            int wrappedLen = dis.readInt();
            byte[] wrapped = new byte[wrappedLen];
            dis.readFully(wrapped);
            appendLog("Received wrapped session (" + wrappedLen + " bytes)");

            // unwrap (rsa decrypt)
            byte[] session = CryptoUtils.rsaDecrypt(wrapped, rsaPair.getPrivate());
            // session := aesKey(32) || iv(12)
            lastAesKeyBytes = new byte[32];
            lastIv = new byte[CryptoUtils.GCM_IV_LENGTH];
            System.arraycopy(session, 0, lastAesKeyBytes, 0, 32);
            System.arraycopy(session, 32, lastIv, 0, lastIv.length);

            // 3) filename + length + encrypted bytes
            String filename = dis.readUTF();
            lastFilename = filename;
            long encLen = dis.readLong();
            appendLog("Receiving '" + filename + "' (encrypted bytes: " + encLen + ")");

            // read encrypted bytes fully
            File encOut = new File("server_received_" + filename + ".enc");
            try (FileOutputStream fos = new FileOutputStream(encOut)) {
                byte[] buf = new byte[8192];
                long remaining = encLen;
                int r;
                while (remaining > 0 && (r = dis.read(buf, 0, (int)Math.min(buf.length, remaining))) > 0) {
                    fos.write(buf, 0, r);
                    remaining -= r;
                }
            }

            // load encrypted bytes into memory (optional) for manual decrypt button
            try (FileInputStream fis = new FileInputStream(encOut);
                 ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
                byte[] b = new byte[8192];
                int rr;
                while ((rr = fis.read(b)) > 0) bos.write(b, 0, rr);
                lastEncryptedBytes = bos.toByteArray();
            }

            appendLog("Saved encrypted file (no decrypt): " + encOut.getAbsolutePath()
                    + " (" + lastEncryptedBytes.length + " bytes)");

            // enable manual decrypt button
            SwingUtilities.invokeLater(() -> decryptBtn.setEnabled(true));

            // ack
            dos.writeUTF("OK");
            dos.flush();

        } catch (Exception ex) {
            appendLog("Client handler error: " + ex.getMessage());
            ex.printStackTrace();
        } finally {
            try { s.close(); } catch (IOException ignored) {}
        }
    }


    private void manualDecrypt() {
        if (lastAesKeyBytes == null || lastIv == null) {
            appendLog("No AES session key/IV available. Cannot decrypt.");
            return;
        }

        try {
            // Prefer decrypting from saved .enc file if exists
            File encFile = new File("server_received_" + lastFilename + ".enc");
            byte[] encryptedData;
            if (encFile.exists()) {
                try (FileInputStream fis = new FileInputStream(encFile);
                     ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
                    byte[] b = new byte[8192];
                    int r;
                    while ((r = fis.read(b)) > 0) bos.write(b, 0, r);
                    encryptedData = bos.toByteArray();
                }
            } else if (lastEncryptedBytes != null) {
                encryptedData = lastEncryptedBytes;
            } else {
                appendLog("Encrypted data not found.");
                return;
            }

            SecretKey k = CryptoUtils.secretKeyFromBytes(lastAesKeyBytes);
            byte[] plain = CryptoUtils.aesGcmDecrypt(encryptedData, k, lastIv);
            File out = new File("server_manual_decrypted_" + lastFilename);
            try (FileOutputStream fos = new FileOutputStream(out)) {
                fos.write(plain);
            }
            appendLog("Manual decrypt saved to: " + out.getAbsolutePath());
        } catch (Exception ex) {
            appendLog("Manual decrypt failed: " + ex.getMessage());
            ex.printStackTrace();
        }
    }


    private void appendLog(String s) {
        SwingUtilities.invokeLater(() -> {
            logArea.append(s + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            Server gui = new Server();
            gui.setVisible(true);
        });
    }
}
