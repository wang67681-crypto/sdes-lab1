import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * S-DES TCP 服务器（第 3 关扩展）。
 *
 * 与客户端共享同一 10 bit 密钥，监听指定端口，接收客户端发来的密文（十六进制串），
 * 用共享密钥逐字节解密并打印明文，同时把结果回显给客户端。
 *
 * 运行：java SDESServer
 */
public class SDESServer {

    public static void main(String[] args) {
        int port = 8888;             // 监听端口
        String key = "1010000010";   // 双方共享的 10 bit 密钥

        try (ServerSocket server = new ServerSocket(port)) {
            System.out.println("S-DES 服务器已启动，监听端口 " + port + "，共享密钥 " + key);

            // 循环等待并处理客户端连接
            while (true) {
                try (Socket socket = server.accept()) {
                    System.out.println("客户端已连接: " + socket.getRemoteSocketAddress());
                    BufferedReader in = new BufferedReader(
                            new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                    PrintWriter out = new PrintWriter(
                            new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);

                    String line;
                    while ((line = in.readLine()) != null) {   // 逐行读取密文（十六进制）
                        String cipher = line.trim();
                        if (cipher.isEmpty()) {
                            continue;
                        }
                        try {
                            String plain = SDES.decryptString(cipher, key);
                            System.out.println("收到密文: " + cipher);
                            System.out.println("解密明文: " + plain);
                            out.println("服务器已解密: " + plain);   // 回显
                        } catch (Exception ex) {
                            out.println("解密失败: " + ex.getMessage());
                        }
                    }
                } catch (IOException e) {
                    System.err.println("处理连接出错: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("服务器启动失败: " + e.getMessage());
        }
    }
}
