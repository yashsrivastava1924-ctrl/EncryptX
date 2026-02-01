import java.awt.*;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.SecretKey;
import javax.swing.*;

public class Client2 extends JFrame {
    private final JTextField fileField = new JTextField(20);
    private final JButton browseBtn = new JButton("Browse");
    private final JComboBox<String> algoBox = new JComboBox<>(new String[]{"AES-256"});
    private final JTextField ipField = new JTextField("127.0.0.1", 10);
    private final JTextField portField = new JTextField("8080", 6);
    private final JButton sendBtn = new JButton("Send File");
    private final JProgressBar progressBar = new JProgressBar(0, 100);
    private final JTextArea statusArea = new JTextArea(6, 40);

    private File chosenFile;
    private final ExecutorService pool = Executors.newSingleThreadExecutor();

    public Client2() {
        super("Secure File Transfer - Client");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();

        c.gridx = 0; c.gridy = 0; c.anchor = GridBagConstraints.WEST;
        add(new JLabel("Select File"), c);
        c.gridx = 1;
        add(browseBtn, c);
        c.gridx = 2; c.gridwidth = 2;
        fileField.setEditable(false);
        add(fileField, c);

        c.gridx = 0; c.gridy = 1; c.gridwidth = 1;
        add(new JLabel("Encryption Algorithm"), c);
        c.gridx = 1; c.gridwidth = 3;
        add(algoBox, c);

        c.gridx = 0; c.gridy = 2; c.gridwidth = 1;
        add(new JLabel("Server IP"), c);
        c.gridx = 1;
        add(ipField, c);
        c.gridx = 2;
        add(portField, c);

        c.gridx = 0; c.gridy = 3; c.gridwidth = 3; c.insets = new Insets(8,0,0,0);
        add(sendBtn, c);

        c.gridx = 0; c.gridy = 4; c.gridwidth = 1; c.insets = new Insets(6,0,0,0);
        add(new JLabel("Progress"), c);
        c.gridx = 1; c.gridwidth = 3;
        progressBar.setPreferredSize(new Dimension(350, 20));
        add(progressBar, c);

        c.gridx = 0; c.gridy = 5; c.gridwidth = 1; c.insets = new Insets(6,0,0,0);
        add(new JLabel("Status"), c);
        c.gridx = 1; c.gridwidth = 3;
        statusArea.setEditable(false);
        JScrollPane sp = new JScrollPane(statusArea);
        sp.setPreferredSize(new Dimension(350, 120));
        add(sp, c);

        browseBtn.addActionListener(e -> onBrowse());
        sendBtn.addActionListener(e -> onSend());

        pack();
        setLocationRelativeTo(null);
    }

    private void onBrowse() {
        JFileChooser fc = new JFileChooser();
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            chosenFile = fc.getSelectedFile();
            fileField.setText(chosenFile.getAbsolutePath());
            appendStatus("Chosen: " + chosenFile.getName());
        }
    }

    private void onSend() {
        if (chosenFile == null) {
            JOptionPane.showMessageDialog(this, "Select a file first.");
            return;
        }
        String host = ipField.getText().trim();
        int port = Integer.parseInt(portField.getText().trim());
        sendBtn.setEnabled(false);
        progressBar.setValue(0);
        pool.submit(() -> sendFile(host, port, chosenFile));
    }

    private void sendFile(String host, int port, File f) {
        try (Socket s = new Socket(host, port);
             DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
             DataInputStream dis = new DataInputStream(new BufferedInputStream(s.getInputStream()))) {

            appendStatus("Connected to " + host + ":" + port);

            // read server key
            int pubLen = dis.readInt();
            byte[] pubBytes = new byte[pubLen];
            dis.readFully(pubBytes);
            PublicKey serverPub = CryptoUtils.publicKeyFromBytes(pubBytes);
            appendStatus("Received server public key (" + pubLen + " bytes)");

            // generate AES key
            SecretKey aesKey = CryptoUtils.generateAESKey();
            byte[] iv = CryptoUtils.generateIV();

            byte[] session = new byte[32 + iv.length];
            System.arraycopy(aesKey.getEncoded(), 0, session, 0, 32);
            System.arraycopy(iv, 0, session, 32, iv.length);

            byte[] wrapped = CryptoUtils.rsaEncrypt(session, serverPub);
            dos.writeInt(wrapped.length);
            dos.write(wrapped);
            dos.flush();
            appendStatus("Sent wrapped AES key (" + wrapped.length + " bytes)");

            // read file bytes (simple)
            byte[] fileBytes = readAllBytes(f);
            appendStatus("Read file bytes: " + fileBytes.length);

            // encrypt
            byte[] encrypted = CryptoUtils.aesGcmEncrypt(fileBytes, aesKey, iv);
            appendStatus("Encrypted size: " + encrypted.length);

            // send filename + length
            dos.writeUTF(f.getName());
            dos.writeLong(encrypted.length);

            // stream encrypted bytes and update progress
            ByteArrayInputStream bis = new ByteArrayInputStream(encrypted);
            byte[] buf = new byte[8192];
            int r;
            long sent = 0;
            long total = encrypted.length;
            while ((r = bis.read(buf)) > 0) {
                dos.write(buf, 0, r);
                sent += r;
                int p = (int)((sent * 100) / total);
                final int percent = p;
                SwingUtilities.invokeLater(() -> progressBar.setValue(percent));
            }
            dos.flush();
            appendStatus("Encrypted file sent.");

            String ack = dis.readUTF();
            appendStatus("Server ACK: " + ack);

        } catch (Exception ex) {
            appendStatus("Send error: " + ex.getMessage());
            ex.printStackTrace();
        } finally {
            SwingUtilities.invokeLater(() -> {
                sendBtn.setEnabled(true);
                progressBar.setValue(0);
            });
        }
    }

    private byte[] readAllBytes(File f) throws IOException {
        try (FileInputStream fis = new FileInputStream(f);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] b = new byte[8192];
            int r;
            while ((r = fis.read(b)) > 0) bos.write(b, 0, r);
            return bos.toByteArray();
        }
    }

    private void appendStatus(String s) {
        SwingUtilities.invokeLater(() -> {
            statusArea.append(s + "\n");
            statusArea.setCaretPosition(statusArea.getDocument().getLength());
        });
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            Client2 obj = new Client2();
            obj.setVisible(true);
        });
    }
}
