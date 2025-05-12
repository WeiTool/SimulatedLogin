package com.srun.login;

import com.srun.login.utils.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.InputMismatchException;
import java.util.Map;
import java.util.Scanner;

import com.google.gson.Gson;

public class Main {

    private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0";
    private static final String GET_CHALLENGE_API = "http://172.16.130.31/cgi-bin/get_challenge";
    private static final String SRUN_PORTAL_API = "http://172.16.130.31/cgi-bin/srun_portal";
    private static final int N = 200;
    private static final int AC_ID = 7;
    private static final String ENC_VER = "srun_bx1";
    private static final int UTYPE = 1;

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

        String username = "yourUsername@ctc";//修改成自己的用户名 @ctc是宿舍区域 @ynufe是教学区域
        String password = "yourPassword";//修改成自己的密码

        try {
            switch (choice) {
                case 1:
                    Map<String, Object> loginResult = login(username, password, "", true);
                    System.out.println(new Gson().toJson(loginResult));
                    break;
                case 2:
                    Map<String, Object> logoutResult = logout(username, "", true);
                    System.out.println(new Gson().toJson(logoutResult));
                    break;
                default:
                    System.out.println("错误：无效选项，请输入 1 或 2");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Map<String, Object> login(String username, String password, String clientIp, boolean autoDetect) {
        Map<String, Object> result = new HashMap<>();
        try {
            if (autoDetect && (clientIp == null || clientIp.isEmpty())) {
                clientIp = detectIp(username);
                System.out.println("自动检测到 IP: " + clientIp);
            }

            Map<String, String> challengeData = getChallenge(username, clientIp);
            String token = challengeData.get("challenge");
            System.out.println("获取到的token为:" + token);
            String updatedIp = challengeData.get("online_ip");

            if (!updatedIp.equals(clientIp)) {
                System.out.println("服务器返回更新 IP: " + updatedIp);
                clientIp = updatedIp;
            }

            String hmd5 = Md5.md5(password, token);
            System.out.println("获取到的加密密码(没有加{MD5}修饰)为:"+hmd5);
            String info = getInfo(username, password, clientIp, token);
            System.out.println("获取到的info为:"+info);
            String chksum = Sha1.Sha1(username, hmd5, AC_ID, clientIp, N, UTYPE, info, token);
            System.out.println("获取到的校验码chksum为:"+chksum);

            String url = buildLoginUrl(username, hmd5, clientIp, info, chksum);
            String response = sendGetRequest(url);

            result = parseJsonp(response);
        } catch (Exception e) {
            result.put("error", e.getMessage());
            result.put("ecode", -1);
        }
        return result;
    }

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

    private static String getInfo(String username, String password, String ip, String token) {
        String infoJson = String.format(
                "{\"username\":\"%s\",\"password\":\"%s\",\"ip\":\"%s\",\"acid\":%d,\"enc_ver\":\"%s\"}",
                username, password, ip, AC_ID, ENC_VER
        );
        byte[] xenBytes = XEncoder.xEncode(infoJson, token);
        CustomB64Encoder encoder = new CustomB64Encoder();
        return "{SRBX1}" + encoder.encode(xenBytes);
    }

    private static String buildLoginUrl(String username, String hmd5, String clientIp, String info, String chksum) {
        return SRUN_PORTAL_API + "?callback=sdu"
                + "&action=login"
                + "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                + "&password={MD5}" + hmd5
                + "&ac_id=" + AC_ID
                + "&ip=" + URLEncoder.encode(clientIp, StandardCharsets.UTF_8)
                + "&info=" + URLEncoder.encode(info, StandardCharsets.UTF_8)
                + "&chksum=" + chksum
                + "&n=" + N
                + "&type=" + UTYPE
                + "&_=" + (System.currentTimeMillis() / 1000);
    }

    private static String buildLogoutUrl(String username, String clientIp) {
        return SRUN_PORTAL_API + "?callback=sdu"
                + "&action=logout"
                + "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                + "&ip=" + URLEncoder.encode(clientIp, StandardCharsets.UTF_8)
                + "&ac_id=" + AC_ID
                + "&_=" + (System.currentTimeMillis() / 1000); // 时间戳参数
    }

    private static String sendGetRequest(String url) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("User-Agent", USER_AGENT);

        try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) {
                response.append(line);
            }
            return response.toString();
        }
    }

    private static Map<String, Object> parseJsonp(String jsonp) {
        Map<String, Object> result = new HashMap<>();
        if (jsonp.startsWith("sdu(") && jsonp.endsWith(")")) {
            String jsonStr = jsonp.substring(4, jsonp.length() - 1);
            result.put("res", jsonStr);
        }
        return result;
    }

    public static Map<String, String> getChallenge(String username, String clientIp) throws IOException {
        Map<String, String> result = new HashMap<>();
        HttpURLConnection conn = null;

        try {
            String timestamp = String.valueOf(System.currentTimeMillis() / 1000 - 2);
            String url = GET_CHALLENGE_API + "?callback=sdu&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                    + "&ip=" + URLEncoder.encode(clientIp, StandardCharsets.UTF_8)
                    + "&_=" + timestamp;

            URL obj = new URL(url);
            conn = (HttpURLConnection) obj.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", USER_AGENT);

            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                throw new IOException("HTTP请求失败，状态码: " + responseCode);
            }

            try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = in.readLine()) != null) {
                    response.append(line);
                }

                String jsonStr = response.toString();
                if (!jsonStr.startsWith("sdu(") || !jsonStr.endsWith(")")) {
                    throw new IOException("无效的JSONP格式");
                }
                jsonStr = jsonStr.substring(4, jsonStr.length() - 1);

                String challenge = extractJsonField(jsonStr, "challenge");
                String onlineIp = extractJsonField(jsonStr, "online_ip");

                result.put("challenge", challenge);
                result.put("online_ip", onlineIp != null ? onlineIp : clientIp);
            }
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
        return result;
    }

    public static String detectIp(String username) {
        try {
            String timestamp = String.valueOf(System.currentTimeMillis() / 1000 - 2);
            String url = GET_CHALLENGE_API + "?callback=sdu&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                    + "&ip=&_=" + timestamp;

            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", USER_AGENT);

            try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String jsonStr = in.readLine();
                if (jsonStr.startsWith("sdu(") && jsonStr.endsWith(")")) {
                    jsonStr = jsonStr.substring(4, jsonStr.length() - 1);
                    String ip = extractJsonField(jsonStr, "online_ip");
                    if (ip != null && !ip.isEmpty()) {
                        return ip;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("[WARN] 自动检测IP失败: " + e.getMessage());
        }
        return getLocalIp();
    }

    private static String getLocalIp() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("8.8.8.8", 80));
            return ((InetSocketAddress) socket.getLocalSocketAddress()).getAddress().getHostAddress();
        } catch (IOException e) {
            return "0.0.0.0";
        }
    }

    private static String extractJsonField(String jsonStr, String key) {
        int start = jsonStr.indexOf("\"" + key + "\":");
        if (start == -1) return null;
        start = jsonStr.indexOf('"', start + key.length() + 3) + 1;
        int end = jsonStr.indexOf('"', start);
        return jsonStr.substring(start, end);
    }
}
