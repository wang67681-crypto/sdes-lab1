import java.util.Arrays;

/**
 * S-DES（简化版 DES）核心算法。
 *
 * 分组长度 8 bit，密钥长度 10 bit。
 * 置换表采用教材标准 S-DES（Stallings）；S 盒中 S-box2（即 S1）按课程文档调整，
 * 其余（含 S-box1 / S0）均与教材一致。
 */
public class SDES {

    // ==================== 置换表（下标为 1 起始，即第 1 位对应字符串下标 0）====================

    /** P10：10 位密钥的初始置换 */
    public static final int[] P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
    /** P8：从 10 位中选出 8 位作为子密钥 */
    public static final int[] P8 = {6, 3, 7, 4, 8, 5, 10, 9};
    /** IP：初始置换 */
    public static final int[] IP = {2, 6, 3, 1, 4, 8, 5, 7};
    /** IP^-1：逆初始置换 */
    public static final int[] IP_INV = {4, 1, 3, 5, 7, 2, 8, 6};
    /** E/P：扩展置换，把 4 位扩成 8 位 */
    public static final int[] EP = {4, 1, 2, 3, 2, 3, 4, 1};
    /** P4：轮函数末尾的 4 位置换 */
    public static final int[] P4 = {2, 4, 3, 1};

    // ==================== S 盒（4 位输入 -> 2 位输出，行=首尾两位，列=中间两位）====================

    /** S0（即文档中的 S-box1） */
    public static final int[][] S0 = {
        {1, 0, 3, 2},
        {3, 2, 1, 0},
        {0, 2, 1, 3},
        {3, 1, 3, 2}
    };

    /** S1（即文档中的 S-box2）—— 以课程文档为准，第 2、3 行与教材标准值不同 */
    public static final int[][] S1 = {
        {0, 1, 2, 3},
        {2, 3, 1, 0},
        {3, 0, 1, 2},
        {2, 1, 0, 3}
    };

    // ==================== 基础工具 ====================

    /** 按置换表重排位串（table 为 1 起始的位置索引） */
    public static String permute(String bits, int[] table) {
        StringBuilder sb = new StringBuilder(table.length);
        for (int i : table) {
            sb.append(bits.charAt(i - 1));
        }
        return sb.toString();
    }

    /** 循环左移 n 位 */
    public static String leftShift(String bits, int n) {
        return bits.substring(n) + bits.substring(0, n);
    }

    /** 逐位异或，返回等长位串 */
    public static String xor(String a, String b) {
        StringBuilder sb = new StringBuilder(a.length());
        for (int i = 0; i < a.length(); i++) {
            sb.append(a.charAt(i) == b.charAt(i) ? '0' : '1');
        }
        return sb.toString();
    }

    /** S 盒查表：4 位输入 -> 2 位输出 */
    public static String sbox(String fourBits, int[][] box) {
        // 行 = 第 1、4 位；列 = 第 2、3 位
        int row = Integer.parseInt("" + fourBits.charAt(0) + fourBits.charAt(3), 2);
        int col = Integer.parseInt("" + fourBits.charAt(1) + fourBits.charAt(2), 2);
        int val = box[row][col];
        return (val >= 2 ? "" : "0") + Integer.toBinaryString(val); // 补成 2 位
    }

    /** 轮函数 F(R, K)：扩展 -> 异或 -> S 盒 -> P4 */
    public static String f(String right4, String key8) {
        String expanded = permute(right4, EP);        // 4 位 -> 8 位
        String mixed = xor(expanded, key8);           // 与子密钥异或
        String s0 = sbox(mixed.substring(0, 4), S0);  // 前 4 位进 S0
        String s1 = sbox(mixed.substring(4, 8), S1);  // 后 4 位进 S1
        return permute(s0 + s1, P4);                  // 合成 4 位再 P4
    }

    /** 轮函数 fk：返回新的左半 = L 异或 F(R, K) */
    public static String fk(String left4, String right4, String key8) {
        return xor(left4, f(right4, key8));
    }

    // ==================== 密钥扩展（10 位 -> K1、K2 各 8 位）====================

    /** 生成两个子密钥 K1、K2 */
    public static String[] keyGen(String key10) {
        String p10 = permute(key10, P10);
        String l = p10.substring(0, 5), r = p10.substring(5);

        String l1 = leftShift(l, 1), r1 = leftShift(r, 1); // LS-1（左移 1 位）
        String k1 = permute(l1 + r1, P8);

        String l2 = leftShift(l1, 2), r2 = leftShift(r1, 2); // LS-2（在 LS-1 基础上再左移 2 位）
        String k2 = permute(l2 + r2, P8);

        return new String[]{k1, k2};
    }

    // ==================== 加 / 解密 ====================

    /** 加密：8 位明文 + 10 位密钥 -> 8 位密文 */
    public static String encrypt(String plain8, String key10) {
        String[] keys = keyGen(key10);
        String ip = permute(plain8, IP);
        String l = ip.substring(0, 4), r = ip.substring(4);

        String l1 = fk(l, r, keys[0]);  // 第 1 轮用 K1
        String l2 = fk(r, l1, keys[1]); // 交换后第 2 轮用 K2
        return permute(l2 + l1, IP_INV);
    }

    /** 解密：8 位密文 + 10 位密钥 -> 8 位明文（子密钥顺序相反） */
    public static String decrypt(String cipher8, String key10) {
        String[] keys = keyGen(key10);
        String ip = permute(cipher8, IP);
        String l = ip.substring(0, 4), r = ip.substring(4);

        String l1 = fk(l, r, keys[1]);  // 第 1 轮用 K2
        String l2 = fk(r, l1, keys[0]); // 交换后第 2 轮用 K1
        return permute(l2 + l1, IP_INV);
    }

    // ==================== 字节 <-> 8 位二进制 转换（供字符串模式使用）====================

    /** 一个字节（0~255）-> 8 位二进制字符串 */
    public static String byteToBits(int b) {
        String s = Integer.toBinaryString(b & 0xFF);
        while (s.length() < 8) {
            s = "0" + s;
        }
        return s;
    }

    /** 8 位二进制字符串 -> 字节值（0~255） */
    public static int bitsToByte(String bits) {
        return Integer.parseInt(bits, 2);
    }

    /** 整数 k（0~1023）-> 10 位二进制密钥字符串 */
    public static String keyFromInt(int k) {
        String s = Integer.toBinaryString(k);
        while (s.length() < 10) {
            s = "0" + s;
        }
        return s;
    }

    // ==================== 字符串模式（逐字节加解密，密文用十六进制表示）====================

    /** 字符串 -> 逐字节加密 -> 十六进制串（每字节两位） */
    public static String encryptString(String text, String key10) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            int b = text.charAt(i) & 0xFF;                    // 取字符低 8 位作为 1 字节
            String cipher = encrypt(byteToBits(b), key10);     // 加密该字节
            hex.append(String.format("%02X", bitsToByte(cipher)));
        }
        return hex.toString();
    }

    /** 十六进制串 -> 逐字节解密 -> 字符串 */
    public static String decryptString(String hex, String key10) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("hex length must be even");
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i + 1 < hex.length(); i += 2) {
            int b = Integer.parseInt(hex.substring(i, i + 2), 16); // 两位十六进制 -> 字节
            String plain = decrypt(byteToBits(b), key10);           // 解密该字节
            sb.append((char) bitsToByte(plain));
        }
        return sb.toString();
    }

    // ==================== 自测（本课程自定义 S-box2 下的参考向量）====================

    public static void main(String[] args) {
        String key = "1010000010";
        String plain = "01110010";
        String cipher = encrypt(plain, key);
        String decrypted = decrypt(cipher, key);

        System.out.println("密钥 K    = " + key);
        System.out.println("明文 P    = " + plain);
        System.out.println("密文 C    = " + cipher);
        System.out.println("解密还原  = " + decrypted);
        System.out.println("加解密自洽= " + decrypted.equals(plain));
        System.out.println("K1/K2     = " + Arrays.toString(keyGen(key)));
    }
}
