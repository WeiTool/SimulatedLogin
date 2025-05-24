package com.srun.login;

import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.srun.login.utils.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import com.google.gson.Gson;
import com.srun.login.utils.Base64;

public class Main {
    /***
     * 用户代理标识，模拟浏览器请求
     */
    private static final Gson PRETTY_GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0";
    // 获取挑战令牌的API地址
    private static final String GET_CHALLENGE_API = "http://172.16.130.31/cgi-bin/get_challenge";
    // 登录认证的API地址
    private static final String SRUN_PORTAL_API = "http://172.16.130.31/cgi-bin/srun_portal";
    // 网络请求的固定参数N
    private static final int N = 200;
    // 认证服务的ID（acid）
    private static final int AC_ID = 7;
    // 加密版本标识符
    private static final String ENC_VER = "srun_bx1";
    // 用户类型参数
    private static final int UTYPE = 1;

    /***
     * 主方法：程序入口，执行登录并输出结果
     */
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("请选择操作：");
        System.out.println("1. 登录");
        System.out.println("2. 退出");
        System.out.print("请输入数字 (1/2): ");

        int choice;
        try {
            choice = scanner.nextInt();
        } catch (InputMismatchException e) {
            System.out.println("错误：请输入数字 1 或 2");
            return;
        }

        String username = "202305006401@ctc"; // 硬编码用户名（可改为动态输入）
        String password = "299053xyh";         // 硬编码密码（可改为动态输入）

        try {
            switch (choice) {
                case 1:
                    Map<String, Object> loginResult = login(username, password, "", true);
                    System.out.println(PRETTY_GSON.toJson(loginResult));
                    break;
                case 2:
                    Map<String, Object> logoutResult = logout(username, "", true);
                    System.out.println(PRETTY_GSON.toJson(logoutResult));
                    break;
                default:
                    System.out.println("错误：无效选项，请输入 1 或 2");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /***
     * 登录认证核心逻辑
     */
    public static Map<String, Object> login(String username, String password, String clientIp, boolean autoDetect) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 自动检测IP逻辑
            if (autoDetect && (clientIp == null || clientIp.isEmpty())) {
                clientIp = detectIp(username); // 调用IP检测方法
                System.out.println("自动检测到 IP: " + clientIp); // 调试输出
            }

            // 获取挑战令牌和服务器IP
            Map<String, String> challengeData = getChallenge(username, clientIp);
            String token = challengeData.get("challenge"); // 从响应中提取token
            System.out.println("获取到的token为:" + token); // 调试输出
            String updatedIp = challengeData.get("online_ip"); // 从响应中提取IP

            // 检查IP是否需要更新
            if (!updatedIp.equals(clientIp)) {
                System.out.println("服务器返回更新 IP: " + updatedIp); // 调试输出
                clientIp = updatedIp; // 更新客户端IP
            }

            // 加密处理
            String hmd5 = Md5.md5(password, token); // 生成MD5哈希密码
            System.out.println("获取到的加密密码(没有加{MD5}修饰)为:"+hmd5); // 调试输出
            String info = getInfo(username, password, clientIp, token); // 构造加密的info字段
            System.out.println("获取到的info为:"+info); // 调试输出
            String chksum = Sha1.Sha1(username, hmd5, AC_ID, clientIp, N, UTYPE, info, token); // 生成SHA1校验和
            System.out.println("获取到的校验码chksum为:"+chksum); // 调试输出

            // 构建并发送登录请求
            String url = buildLoginUrl(username, hmd5, clientIp, info, chksum); // 拼接登录URL
            String response = sendGetRequest(url); // 发送HTTP GET请求

            result = parseJsonp(response); // 解析JSONP响应
        } catch (Exception e) {
            // 异常处理：记录错误信息
            result.put("error", e.getMessage());
            result.put("ecode", -1);
        }
        return result; // 返回最终结果
    }

    /**
     * 注销认证核心逻辑
     */
    public static Map<String, Object> logout(String username, String clientIp, boolean autoDetect) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 自动检测IP逻辑
            if (autoDetect && (clientIp == null || clientIp.isEmpty())) {
                clientIp = detectIp(username); // 复用IP检测方法
                System.out.println("自动检测到 IP: " + clientIp);
            }

            // 构建注销URL
            String url = buildLogoutUrl(username, clientIp);
            String response = sendGetRequest(url); // 发送HTTP GET请求

            result = parseJsonp(response); // 解析响应
        } catch (Exception e) {
            result.put("error", e.getMessage());
            result.put("ecode", -1);
        }
        return result;
    }

    /***
     * 构造加密的info字段
     */
    private static String getInfo(String username, String password, String ip, String token) {
        // 构造JSON格式的原始信息
        String infoJson = String.format(
                "{\"username\":\"%s\",\"password\":\"%s\",\"ip\":\"%s\",\"acid\":%d,\"enc_ver\":\"%s\"}",
                username, password, ip, AC_ID, ENC_VER
        );
        // 使用Encode进行加密
        byte[] enBytes = Encode.encode(infoJson, token);
        // 使用Base64Utils进行编码并添加前缀
        return "{SRBX1}" + Base64.customB64encode(enBytes);
    }

    /***
     * 构建登录URL
     */
    private static String buildLoginUrl(String username, String hmd5, String clientIp, String info, String chksum) {
        // 强制编码@为%40
        String encodedUsername = URLEncoder.encode(username, StandardCharsets.UTF_8).replace("@", "%40");
        return SRUN_PORTAL_API + "?callback=sdu"
                + "&action=login"
                + "&username=" + encodedUsername
                + "&password={MD5}" + hmd5
                + "&ac_id=" + AC_ID
                + "&ip=" + URLEncoder.encode(clientIp, StandardCharsets.UTF_8)
                + "&info=" + URLEncoder.encode(info, StandardCharsets.UTF_8)
                + "&chksum=" + chksum
                + "&n=" + N
                + "&type=" + UTYPE
                + "&_=" + (System.currentTimeMillis() / 1000);
    }

    /**
     * 构建注销URL
     */
    private static String buildLogoutUrl(String username, String clientIp) {
        return SRUN_PORTAL_API + "?callback=sdu"
                + "&action=logout"
                + "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                + "&ip=" + URLEncoder.encode(clientIp, StandardCharsets.UTF_8)
                + "&ac_id=" + AC_ID
                + "&_=" + (System.currentTimeMillis() / 1000); // 时间戳参数
    }

    /***
     * 发送HTTP GET请求
     */
    private static String sendGetRequest(String url) throws IOException {
        // 创建HTTP连接
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET"); // 设置请求方法
        conn.setRequestProperty("User-Agent", USER_AGENT); // 添加User-Agent头

        // 读取响应内容
        try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) { // 逐行读取响应
                response.append(line);
            }
            return response.toString(); // 返回完整响应字符串
        }
    }

    /***
     * 解析JSONP响应（简化版）
     */
    private static Map<String, Object> parseJsonp(String jsonp) {
        try {
            if (jsonp.startsWith("sdu(") && jsonp.endsWith(")")) {
                String jsonStr = jsonp.substring(4, jsonp.length() - 1);
                // 直接解析为结构化Map
                return new Gson().fromJson(jsonStr, new TypeToken<Map<String, Object>>(){}.getType());
            }
            return Collections.singletonMap("error", "Invalid JSONP format");
        } catch (Exception e) {
            Map<String, Object> errResult = new HashMap<>();
            errResult.put("error", "Failed to parse response: " + e.getMessage());
            return errResult;
        }
    }

    /***
     * 获取挑战令牌和在线IP
     */
    public static Map<String, String> getChallenge(String username, String clientIp) throws IOException {
        Map<String, String> result = new HashMap<>();
        HttpURLConnection conn = null;
        try {
            // 构建请求URL（含时间戳）
            String timestamp = String.valueOf(System.currentTimeMillis() / 1000 - 2);
            String url = GET_CHALLENGE_API + "?callback=sdu&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                    + "&ip=" + URLEncoder.encode(clientIp, StandardCharsets.UTF_8)
                    + "&_=" + timestamp;

            URL obj = new URL(url);
            conn = (HttpURLConnection) obj.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", USER_AGENT); // 设置请求头

            // 检查HTTP状态码
            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                throw new IOException("HTTP请求失败，状态码: " + responseCode);
            }

            // 读取响应内容
            try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = in.readLine()) != null) {
                    response.append(line);
                }

                String jsonStr = response.toString();
                // 验证JSONP格式
                if (!jsonStr.startsWith("sdu(") || !jsonStr.endsWith(")")) {
                    throw new IOException("无效的JSONP格式");
                }
                jsonStr = jsonStr.substring(4, jsonStr.length() - 1); // 去除包装

                // 提取关键字段
                String challenge = extractJsonField(jsonStr, "challenge");
                String onlineIp = extractJsonField(jsonStr, "online_ip");

                // 存储结果（若online_ip为空则使用原IP）
                result.put("challenge", challenge);
                result.put("online_ip", onlineIp != null ? onlineIp : clientIp);
            }
        } finally {
            if (conn != null) {
                conn.disconnect(); // 确保连接关闭
            }
        }
        return result;
    }

    /***
     * 自动检测客户端IP
     */
    public static String detectIp(String username) {
        try {
            // 构建IP检测URL（IP参数留空）
            String timestamp = String.valueOf(System.currentTimeMillis() / 1000 - 2);
            String url = GET_CHALLENGE_API + "?callback=sdu&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                    + "&ip=&_=" + timestamp;

            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", USER_AGENT);

            // 读取响应并提取IP
            try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String jsonStr = in.readLine();
                if (jsonStr.startsWith("sdu(") && jsonStr.endsWith(")")) {
                    jsonStr = jsonStr.substring(4, jsonStr.length() - 1);
                    String ip = extractJsonField(jsonStr, "online_ip");
                    if (ip != null && !ip.isEmpty()) {
                        return ip; // 返回服务器提供的IP
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[WARN] 自动检测IP失败: " + e.getMessage()); // 异常日志
        }
        return getLocalIp(); // 失败时返回本地IP
    }

    /***
     * 获取本地出口IP
     */
    private static String getLocalIp() {
        try (Socket socket = new Socket()) {
            // 通过连接外部服务器获取本地IP
            socket.connect(new InetSocketAddress("8.8.8.8", 80));
            return ((InetSocketAddress) socket.getLocalSocketAddress()).getAddress().getHostAddress();
        } catch (IOException e) {
            return "0.0.0.0"; // 失败时返回默认IP
        }
    }

    /***
     * 从JSON字符串提取字段值（简易实现）
     */
    private static String extractJsonField(String jsonStr, String key) {
        // 查找字段起始位置
        int start = jsonStr.indexOf("\"" + key + "\":");
        if (start == -1) return null;
        // 定位值起始引号
        start = jsonStr.indexOf('"', start + key.length() + 3) + 1;
        // 定位值结束引号
        int end = jsonStr.indexOf('"', start);
        return jsonStr.substring(start, end); // 截取字段值
    }
}