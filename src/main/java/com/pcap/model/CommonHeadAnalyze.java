package com.pcap.model;


import com.pcap.utils.ByteUtil;

/**
 * Created by sophia on 2018/4/22.
 */
public class CommonHeadAnalyze {
    protected byte[] head;

    /**
     * MAC帧头部解析：有14字节
     *
     * @param head
     */
    public CommonHeadAnalyze(byte[] head) {
        this.head = head;
    }

    public String getSourceMAC() {
        StringBuilder result = new StringBuilder("");
        for (int i = 0; i <= 5; i++) {
            result.append(ByteUtil.byteToHexString(this.head[i]));
            if (i != 5) {
                result.append("-");
            }
        }
        return result.toString();
    }

    public String getDestinationMAC() {
        StringBuilder result = new StringBuilder("");
        for (int i = 6; i <= 11; i++) {
            result.append(ByteUtil.byteToHexString(this.head[i]));
            if (i != 11) {
                result.append("-");
            }
        }
        return result.toString();
    }

    /**
     * IP:0X0800
     * ARP:0X0806
     * RARP:0X8035
     *
     * @return
     */
    public String getType() {
        return "0x" + ByteUtil.byteToHexString(this.head[12])
                + ByteUtil.byteToHexString(this.head[13]);
    }
}
