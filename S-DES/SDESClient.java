import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * S-DES TCP 客户端（第 3 关扩展）。
 *
 * 与服务器共享同一 10 bit 密钥，把明文字符串逐字节加密后（十六进制串）通过 TCP 发送，
 * 并接收服务器解密后的回显，演示 S-DES 在 Socket 通信中的应用。
 *
 * 运行：java SDESClient [要发送的明文]
 */
public class SDESClient {

    public static void main(String[] args) {
        String host = "127.0.0.1";  // 服务器地址
        int port = 8888;            // 服务器端口
        String key = "1010000010";  // 双方共享的 10 bit 密钥
        String message = (args.length > 0) ? args[0] : "Hello S-DES!";

        try (Socket socket = new Socket(host, port)) {
            PrintWriter out = new PrintWriter(
                    new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

            String cipherHex = SDES.encryptString(message, key);
            out.println(cipherHex);   // 发送密文

            System.out.println("已连接服务器 " + host + ":" + port + "，共享密钥 " + key);
            System.out.println("明文  : " + message);
            System.out.println("密文  : " + cipherHex);
            System.out.println("服务器回复: " + in.readLine());
        } catch (Exception e) {
            System.err.println("客户端错误: " + e.getMessage());
        }
    }
}
