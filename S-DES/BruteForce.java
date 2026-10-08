import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * 暴力破解与封闭测试分析。
 *
 * S-DES 密钥只有 10 bit，全部空间 2^10 = 1024，可以在毫秒级穷举完。
 * 本类提供：
 *  1. crack(...)            多线程穷举所有能匹配明文/密文对的密钥；
 *  2. collisionAnalysis(...) 固定明文，统计 1024 个密钥映射到各密文的分布，
 *                            用于验证 "不同密钥可能加密得到相同密文"（鸽巢原理）。
 */
public class BruteForce {

    /** 多线程暴力破解：返回所有满足 encrypt(plain,key)==cipher 的密钥 */
    public static List<String> crack(String plain, String cipher, int threads) {
        final int TOTAL = 1 << 10; // 1024
        int n = Math.max(1, threads);
        ExecutorService pool = Executors.newFixedThreadPool(n);
        List<Future<List<String>>> futures = new ArrayList<>();

        // 把 [0, 1024) 的密钥空间按线程数切成若干段，每个线程负责一段
        int chunk = Math.max(1, (TOTAL + n - 1) / n);
        for (int start = 0; start < TOTAL; start += chunk) {
            final int from = start;
            final int to = Math.min(start + chunk, TOTAL);
            futures.add(pool.submit(() -> {
                List<String> found = new ArrayList<>();
                for (int k = from; k < to; k++) {
                    String key = SDES.keyFromInt(k);
                    if (SDES.encrypt(plain, key).equals(cipher)) {
                        found.add(key);
                    }
                }
                return found;
            }));
        }

        List<String> result = new ArrayList<>();
        try {
            for (Future<List<String>> f : futures) {
                result.addAll(f.get());
            }
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        } finally {
            pool.shutdown();
        }
        return result;
    }

    /** 封闭测试：固定明文 P，统计各密文被多少个密钥映射到，返回摘要文字 */
    public static String collisionAnalysis(String plain) {
        final int TOTAL = 1 << 10;
        int[] count = new int[256]; // 索引即密文对应的字节值

        for (int k = 0; k < TOTAL; k++) {
            String cipher = SDES.encrypt(plain, SDES.keyFromInt(k));
            count[SDES.bitsToByte(cipher)]++;
        }

        int distinct = 0; // 实际能映射到的不同密文个数
        int max = 0, maxCipher = 0;
        for (int c = 0; c < 256; c++) {
            if (count[c] > 0) distinct++;
            if (count[c] > max) {
                max = count[c];
                maxCipher = c;
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("明文 P            = ").append(plain).append('\n');
        sb.append("密钥空间大小      = 1024\n");
        sb.append("明文/密文空间大小 = 256\n");
        sb.append("实际映射到的不同密文数 = ").append(distinct).append('\n');
        sb.append("平均每个密文对应的密钥数 = ")
          .append(String.format("%.2f", 1024.0 / distinct)).append('\n');
        sb.append("最多有 ").append(max).append(" 个密钥映射到同一密文 ")
          .append(SDES.byteToBits(maxCipher)).append('\n');
        sb.append("结论: ").append(max > 1
                ? "存在密钥碰撞（不同密钥 -> 相同密文），符合鸽巢原理"
                : "该明文下未发现碰撞").append('\n');
        return sb.toString();
    }

    /** 简单自测 */
    public static void main(String[] args) {
        String plain = "01110010";
        String cipher = "00111010";
        long t0 = System.nanoTime();
        List<String> keys = crack(plain, cipher, Runtime.getRuntime().availableProcessors());
        long t1 = System.nanoTime();
        System.out.println("明密文对: " + plain + " -> " + cipher);
        System.out.println("找到密钥 " + keys.size() + " 个: " + keys);
        System.out.printf("耗时 %.3f ms%n", (t1 - t0) / 1_000_000.0);
        System.out.println();
        System.out.println(collisionAnalysis(plain));
    }
}
