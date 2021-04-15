package com.pcap;

import com.alibaba.fastjson.JSONObject;
import com.pcap.utils.LinuxLogin;
import com.pcap.utils.PcapParser;
import com.trilead.ssh2.Connection;
import org.apache.commons.lang.time.DateUtils;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.List;

/**
 * @ClassName PcapTest
 * @Description TODO
 * @Author wxw
 * @Date 2021-04-15 13:53
 **/
public class PcapTest {

    @Test
    public  void testParser(){
        String filePath = "";

        Connection connection = LinuxLogin.getConn("", 22, "root", "");
        try (
                InputStream inputStream = LinuxLogin.readFile(connection, filePath);

        ) {

            List<JSONObject> list = PcapParser.parse(inputStream);
            list.stream().parallel().forEach(s->System.out.println(s));

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        } finally {
            assert connection != null;
            connection.close();
        }

    }
}
