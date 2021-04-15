package com.pcap.utils;


import com.trilead.ssh2.*;
import lombok.Data;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * @ClassName LinuxLogin
 * @Description TODO
 * @Author wxw
 * @Date 2020/12/3 11:29
 **/

@Data
public class LinuxLogin {

    private static Logger log = LoggerFactory.getLogger(LinuxLogin.class);

    private static final Long TIME_OUT=2000L;

    private static  Connection conn;

    /**
     * 获取conn
     * @param ip
     * @param port
     * @param user
     * @param pwd
     * @return
     */
    public  static Connection getConn(String ip, int port, String user, String pwd) {

            conn = new Connection(ip, port);
            if (conn.isAuthenticationComplete()) {
                return conn;
            }
            try {
                conn.connect();
                boolean isAuthenticated = conn.authenticateWithPassword(user, pwd);
                if (!isAuthenticated) {
                    throw new Exception("authentication failed！");
                }
                return conn;
            } catch (Exception e) {
                e.printStackTrace();
            }

        return null;
    }

    /**
     * 获取session
     * @param conn
     * @return
     * @throws IOException
     */
    public static Session getSession(Connection conn) throws IOException {
        Session session = conn.openSession();
        return session;
    }

    /**
     * 获取SFTPv3Client
     * @param conn
     * @return
     * @throws IOException
     */
    public static SFTPv3Client getClient(Connection conn) throws IOException {
        SFTPv3Client client = new SFTPv3Client(conn);
        return client;
    }
    /**
     * 读取远端文件流
     * @param filePath
     * @return
     * @throws IOException
     */
    public static InputStream readFile(Connection conn, String filePath) throws IOException, InterruptedException {
        Session session = getSession(conn);
        //获取文件大小
        session.execCommand("du -b ".concat(filePath));
        InputStream sizeIn = new StreamGobbler(session.getStdout());
        //将字节流向字符流的转换。
        InputStreamReader isr = new InputStreamReader(sizeIn);//读取
        //创建字符流缓冲区
        BufferedReader bufr = new BufferedReader(isr);//缓冲
        String line;
        int fileSize = 0;
        while((line = bufr.readLine())!=null){
            String[] fileAttr = line.split("\t");
            fileSize = Integer.parseInt(fileAttr[0]);
        }
        isr.close();
        session.close();

        session = getSession(conn);
        session.execCommand("cat ".concat(filePath));
        //休眠2秒再获取返回信息，防止网络传输过程中延迟造成读取文件大小为0字节
        Thread.sleep(2000);
        InputStream is = new StreamGobbler(session.getStdout());
        session.waitForCondition(ChannelCondition.EXIT_STATUS, TIME_OUT);
        //获取指令是否成功执行:0－成功,非0－失败.
        //int ret = session.getExitStatus();

        int i = 0;
        while (fileSize != is.available()) {
            i++;
            Thread.sleep(1000);
        }
        session.close();
        return is;
    }
    /**
     * 判断远程服务器路径是否是目录
     * @param client
     * @param path
     * @return
     */
    private static boolean isDirectory(SFTPv3Client client, String path) {
        try {
            SFTPv3FileAttributes attributes = client.stat(path);
            return attributes.isDirectory();
        } catch(IOException e) {
            log.error("获取文件属性异常", e);
        }
        return false;
    }
}

