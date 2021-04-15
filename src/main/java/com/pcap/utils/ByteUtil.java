package com.pcap.utils;

public class ByteUtil {
    /**
     * 字节的16进制表示返回字符串
     *
     * @param b
     * @return String
     */
    public static String byteToHexString(byte b) {
        String s = Integer.toHexString(b & 0xff);
        if (s.length() < 2) {
            s = "0" + s;
        }
        return s;
    }

    /**
     * 字节转整数类型
     *
     * @param b
     * @return int
     */
    public static int byteToInt(byte b) {
        return (b & 0xff);
    }

    /**
     * 获取字节内指定下标的二进制1或0
     *
     * @param b
     * @param index
     * @return int
     */
    public static int getIndexBit(byte b, int index) {
        if (index >= 8) {
            return b & 0xff;
        } else {
            int a = (int) Math.pow(2, index);
            return (b & a) >> (index);
        }
    }

    /**
     * 从字节中取出4位
     *
     * @param b
     * @param isLow
     * @return int
     */
    public static int getFourBit(byte b, boolean isLow) {
        if (isLow) {
            //如果是低位,与低位全1
            //整数型的16进制表示，int是4字节所以是32位
            return b & 0x0f;
        } else {
            //如果是高位,与高位全1，右移4位
            return (b & 0xf0) >> 4;
        }
    }

    /**
     * 糅合两个字节即构成32位整数
     *
     * @param b1
     * @param b2
     * @return int
     */
    public static int unionByte(byte b1, byte b2) {
        byte c1 = 0, c2 = 0;
        int a = 0;
        a = (((c1 & 0xff) << 24) | ((c2 & 0xff) << 16) | ((b1 & 0xff) << 8) | ((b2 & 0xff)));
        return a;
    }

    public static int unionInt(int b1, int b2) {
        return b1 << 4 | b2;
    }

    public static long unionByte(byte b1, byte b2, byte b3, byte b4) {
        return (((b1 & 0xff) << 24) | ((b2 & 0xff) << 16) | ((b3 & 0xff) << 8) | ((b4 & 0xff) << 0));
    }
}
