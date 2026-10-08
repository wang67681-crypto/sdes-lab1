import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.List;

/**
 * S-DES 图形界面（Swing）。
 *
 * 四个标签页，分别对应作业的第 1~5 关：
 *   1. 单块加解密   —— 8 bit 数据 + 10 bit 密钥（第 1、2 关）
 *   2. 字符串加解密 —— ASCII 字符串按 1 Byte 分组（第 3 关）
 *   3. 暴力破解     —— 多线程穷举密钥并计时（第 4 关）
 *   4. 封闭测试分析 —— 分析密钥碰撞（第 5 关）
 */
public class SDESGUI extends JFrame {

    // 单块模式组件
    private JTextField keyField, dataField, cipherField, k1Field, k2Field;

    // 字符串模式组件
    private JTextField strKeyField;
    private JTextArea strInputArea, strOutputArea;

    // 暴力破解组件
    private JTextField brutePlainField, bruteCipherField, threadField;
    private JTextArea bruteResultArea;

    // 封闭测试组件
    private JTextField analysisPlainField;
    private JTextArea analysisResultArea;

    public SDESGUI() {
        super("S-DES 加解密工具");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(720, 560);
        setLocationRelativeTo(null);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("单块加解密", buildSinglePanel());
        tabs.addTab("字符串加解密", buildStringPanel());
        tabs.addTab("暴力破解", buildBrutePanel());
        tabs.addTab("封闭测试分析", buildAnalysisPanel());
        add(tabs);
    }

    // ==================== 第 1 关：单块加解密 ====================

    private JPanel buildSinglePanel() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(new EmptyBorder(16, 16, 16, 16));

        keyField = new JTextField("1010000010", 12);
        dataField = new JTextField("01110010", 12);
        cipherField = new JTextField(12);
        cipherField.setEditable(false);
        k1Field = new JTextField(12);
        k1Field.setEditable(false);
        k2Field = new JTextField(12);
        k2Field.setEditable(false);

        p.add(row("10 bit 密钥 K :", keyField));
        p.add(row("8 bit  数据 :", dataField));
        p.add(Box.createVerticalStrut(8));

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton encBtn = new JButton("加密");
        JButton decBtn = new JButton("解密");
        btnRow.add(encBtn);
        btnRow.add(decBtn);
        p.add(btnRow);
        p.add(Box.createVerticalStrut(8));

        p.add(row("输出 8 bit   :", cipherField));
        p.add(row("子密钥 K1    :", k1Field));
        p.add(row("子密钥 K2    :", k2Field));

        encBtn.addActionListener((ActionEvent e) -> {
            String key = keyField.getText().trim();
            String data = dataField.getText().trim();
            if (!validBits(key, 10) || !validBits(data, 8)) {
                JOptionPane.showMessageDialog(this,
                        "密钥须为 10 位二进制，数据须为 8 位二进制（只含 0/1）",
                        "输入错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            cipherField.setText(SDES.encrypt(data, key));
            showSubKeys(key);
        });

        decBtn.addActionListener((ActionEvent e) -> {
            String key = keyField.getText().trim();
            String data = dataField.getText().trim();
            if (!validBits(key, 10) || !validBits(data, 8)) {
                JOptionPane.showMessageDialog(this,
                        "密钥须为 10 位二进制，数据须为 8 位二进制（只含 0/1）",
                        "输入错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            cipherField.setText(SDES.decrypt(data, key));
            showSubKeys(key);
        });

        return p;
    }

    private void showSubKeys(String key) {
        String[] keys = SDES.keyGen(key);
        k1Field.setText(keys[0]);
        k2Field.setText(keys[1]);
    }

    // ==================== 第 3 关：字符串加解密 ====================

    private JPanel buildStringPanel() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(new EmptyBorder(16, 16, 16, 16));

        strKeyField = new JTextField("1010000010", 16);
        strInputArea = new JTextArea(4, 40);
        strInputArea.setLineWrap(true);
        strOutputArea = new JTextArea(6, 40);
        strOutputArea.setLineWrap(true);
        strOutputArea.setEditable(false);

        p.add(row("10 bit 密钥 K :", strKeyField));
        p.add(new JLabel("明文 / 密文（ASCII 字符串，按 1 Byte 分组）："));
        p.add(new JScrollPane(strInputArea));
        p.add(Box.createVerticalStrut(8));

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton encBtn = new JButton("加密字符串");
        JButton decBtn = new JButton("解密字符串");
        btnRow.add(encBtn);
        btnRow.add(decBtn);
        p.add(btnRow);
        p.add(Box.createVerticalStrut(8));

        p.add(new JLabel("结果（密文以十六进制显示，每字节两位）："));
        p.add(new JScrollPane(strOutputArea));

        encBtn.addActionListener((ActionEvent e) -> {
            String key = strKeyField.getText().trim();
            if (!validBits(key, 10)) {
                JOptionPane.showMessageDialog(this, "密钥须为 10 位二进制", "输入错误",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            strOutputArea.setText(SDES.encryptString(strInputArea.getText(), key));
        });

        decBtn.addActionListener((ActionEvent e) -> {
            String key = strKeyField.getText().trim();
            if (!validBits(key, 10)) {
                JOptionPane.showMessageDialog(this, "密钥须为 10 位二进制", "输入错误",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            try {
                strOutputArea.setText(SDES.decryptString(strInputArea.getText().trim(), key));
            } catch (IllegalArgumentException ex) {
                JOptionPane.showMessageDialog(this, "密文须为偶数个十六进制字符（如 5B3C...）",
                        "输入错误", JOptionPane.ERROR_MESSAGE);
            }
        });

        return p;
    }

    // ==================== 第 4 关：暴力破解 ====================

    private JPanel buildBrutePanel() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(new EmptyBorder(16, 16, 16, 16));

        brutePlainField = new JTextField("01110010", 12);
        bruteCipherField = new JTextField("00111010", 12);
        int cores = Runtime.getRuntime().availableProcessors();
        threadField = new JTextField(String.valueOf(cores), 6);
        bruteResultArea = new JTextArea(10, 40);
        bruteResultArea.setEditable(false);

        p.add(row("已知明文 (8 bit) :", brutePlainField));
        p.add(row("已知密文 (8 bit) :", bruteCipherField));
        p.add(row("线程数 :", threadField));
        p.add(Box.createVerticalStrut(8));

        JButton runBtn = new JButton("开始暴力破解");
        p.add(runBtn);
        p.add(Box.createVerticalStrut(8));
        p.add(new JScrollPane(bruteResultArea));

        runBtn.addActionListener((ActionEvent e) -> {
            String plain = brutePlainField.getText().trim();
            String cipher = bruteCipherField.getText().trim();
            if (!validBits(plain, 8) || !validBits(cipher, 8)) {
                JOptionPane.showMessageDialog(this, "明文/密文须为 8 位二进制", "输入错误",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            int parsed;
            try {
                parsed = Integer.parseInt(threadField.getText().trim());
            } catch (NumberFormatException ex) {
                parsed = cores;
            }
            final int threads = parsed;

            // 用 SwingWorker 后台执行，避免界面卡顿
            runBtn.setEnabled(false);
            bruteResultArea.setText("破解中……\n");
            new SwingWorker<String, Void>() {
                @Override
                protected String doInBackground() {
                    long t0 = System.nanoTime();
                    List<String> keys = BruteForce.crack(plain, cipher, threads);
                    long t1 = System.nanoTime();
                    StringBuilder sb = new StringBuilder();
                    sb.append("明密文对: ").append(plain).append(" -> ").append(cipher).append('\n');
                    sb.append("找到密钥 ").append(keys.size()).append(" 个:\n");
                    for (String k : keys) {
                        sb.append("  ").append(k).append('\n');
                    }
                    sb.append(String.format("总耗时 %.3f ms（多线程数 %d）%n",
                            (t1 - t0) / 1_000_000.0, threads));
                    return sb.toString();
                }

                @Override
                protected void done() {
                    try {
                        bruteResultArea.setText(get());
                    } catch (Exception ex) {
                        bruteResultArea.setText("破解出错: " + ex.getMessage());
                    }
                    runBtn.setEnabled(true);
                }
            }.execute();
        });

        return p;
    }

    // ==================== 第 5 关：封闭测试分析 ====================

    private JPanel buildAnalysisPanel() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(new EmptyBorder(16, 16, 16, 16));

        analysisPlainField = new JTextField("01110010", 12);
        analysisResultArea = new JTextArea(12, 40);
        analysisResultArea.setEditable(false);

        p.add(row("给定明文 P (8 bit) :", analysisPlainField));
        p.add(Box.createVerticalStrut(8));

        JButton runBtn = new JButton("分析密钥碰撞");
        p.add(runBtn);
        p.add(Box.createVerticalStrut(8));
        p.add(new JScrollPane(analysisResultArea));

        runBtn.addActionListener((ActionEvent e) -> {
            String plain = analysisPlainField.getText().trim();
            if (!validBits(plain, 8)) {
                JOptionPane.showMessageDialog(this, "明文须为 8 位二进制", "输入错误",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            analysisResultArea.setText("分析中……\n");
            new SwingWorker<String, Void>() {
                @Override
                protected String doInBackground() {
                    return BruteForce.collisionAnalysis(plain);
                }

                @Override
                protected void done() {
                    try {
                        analysisResultArea.setText(get());
                    } catch (Exception ex) {
                        analysisResultArea.setText("分析出错: " + ex.getMessage());
                    }
                }
            }.execute();
        });

        return p;
    }

    // ==================== 工具方法 ====================

    /** 校验字符串是否恰好 n 位且只含 0/1 */
    private boolean validBits(String s, int n) {
        if (s == null || s.length() != n) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '0' && c != '1') {
                return false;
            }
        }
        return true;
    }

    /** 一行 = 标签 + 输入框 */
    private JPanel row(String label, JComponent field) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        p.add(new JLabel(label));
        p.add(field);
        return p;
    }

    public static void main(String[] args) {
        // 统一使用中文界面风格，避免乱码
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored) {
            }
            new SDESGUI().setVisible(true);
        });
    }
}
