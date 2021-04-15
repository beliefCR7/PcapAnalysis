package com.pcap.utils;


import com.alibaba.fastjson.JSONObject;
import com.pcap.model.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;


public class PcapParser extends Observable {





   private static ProtocolData protocolData;
   private  static ThreadLocal<byte[]> file_header= ThreadLocal.withInitial(() -> new byte[24]);
	private static ThreadLocal<byte[]> data_header= ThreadLocal.withInitial(() -> new byte[16]);
	private static ThreadLocal<byte[]> content=new ThreadLocal<>();
	private static ThreadLocal<Integer> data_offset=new ThreadLocal<>();
	private static ThreadLocal<byte[]> data_content=new ThreadLocal<>();

	private static Map<Integer, Map<Integer,String>> typeCode=new HashMap<>();

   static {
         Map map0=new HashMap<>();
	   map0.put(0,"Echo Reply——回显应答（Ping应答）");
	   typeCode.put(0,map0);
	   Map map3=new HashMap<>();
	   map3.put(0,"Network Unreachable——网络不可达");
	   map3.put(1,"Host Unreachable——主机不可达");
	   map3.put(2,"Protocol Unreachable——协议不可达");
	   map3.put(3,"Port Unreachable——端口不可达");
	   map3.put(4,"Fragmentation needed but no frag. bit set——需要进行分片但设置不分片比特");
	   map3.put(5,"Source routing failed——源站选路失败");
	   map3.put(6,"Destination network unknown——目的网络未知");
	   map3.put(7,"Destination host unknown——目的主机未知");
	   map3.put(8,"Source host isolated (obsolete)——源主机被隔离（作废不用）");
	   map3.put(9,"Destination network administratively prohibited——目的网络被强制禁止");
	   map3.put(10,"Destination host administratively prohibited——目的主机被强制禁止");
	   map3.put(11,"Network unreachable for TOS——由于服务类型TOS，网络不可达");
	   map3.put(12,"Host unreachable for TOS——由于服务类型TOS，主机不可达");
	   map3.put(13,"Communication administratively prohibited by filtering——由于过滤，通信被强制禁止");
	   map3.put(14,"Host precedence violation——主机越权");
	   map3.put(15,"Precedence cutoff in effect——优先中止生效");
	   typeCode.put(3,map3);

	   Map map4=new HashMap<>();
	   map4.put(0,"Source quench——源端被关闭（基本流控制）");
	   typeCode.put(4,map4);
	   Map map5=new HashMap<>();
	   map5.put(0,"Redirect for network——对网络重定向");
	   map5.put(1,"Redirect for host——对主机重定向");
	   map5.put(2,"Redirect for TOS and network——对服务类型和网络重定向");
	   map5.put(3,"Redirect for TOS and host——对服务类型和主机重定向");
	   typeCode.put(5,map5);
	   Map map8=new HashMap<>();
	   map8.put(0,"Echo request——回显请求（Ping请求）");
	   typeCode.put(8,map8);
	   Map map9=new HashMap<>();
	   map9.put(0,"Router advertisement——路由器通告");
	   typeCode.put(9,map9);
	   Map map10=new HashMap<>();
	   map10.put(0,"Route solicitation——路由器请求");
	   typeCode.put(10,map10);
	   Map map11=new HashMap<>();
	   map11.put(0,"TTL equals 0 during transit——传输期间生存时间为0");
	   map11.put(1,"TTL equals 0 during reassembly——在数据报组装期间生存时间为0");
	   typeCode.put(11,map11);
	   Map map12=new HashMap<>();
	   map12.put(0,"IP header bad (catchall error)——坏的IP首部（包括各种差错）");
	   map12.put(1,"Required options missing——缺少必需的选项");
	   typeCode.put(12,map12);
	   Map map13=new HashMap<>();
	   map13.put(0,"Timestamp request (obsolete)——时间戳请求（作废不用）");
	   typeCode.put(13,map13);
	   Map map14=new HashMap<>();
	   map14.put(0,"Timestamp reply (obsolete)——时间戳应答（作废不用）");
	   typeCode.put(14,map14);
	   Map map15=new HashMap<>();
	   map15.put(0,"Information request (obsolete)——信息请求（作废不用）");
	   typeCode.put(15,map15);
	   Map map16=new HashMap<>();
	   map16.put(0,"Information reply (obsolete)——信息应答（作废不用）");
	   typeCode.put(16,map16);
	   Map map17=new HashMap<>();
	   map17.put(0,"Address mask request——地址掩码请求");
	   typeCode.put(17,map17);
	   Map map18=new HashMap<>();
	   map18.put(0,"Address mask reply——地址掩码应答");
	   typeCode.put(18,map18);

  }

	public static List<JSONObject> parse (InputStream fis) {
		List<JSONObject>  list=new ArrayList<>();

		try {
			byte[] bytes=new byte[24];
			int m = fis.read(bytes);
			file_header.set(bytes);
			if (m > 0) {

				PcapFileHeader fileHeader = parseFileHeader(file_header.get());
				
				if (fileHeader == null) {
					LogUtils.printObj("fileHeader", "null");
				}


				while (m > 0) {
					byte[] dataHeaderByte=new byte[16];
					m = fis.read(dataHeaderByte);
					if(m==0) {
						break;
					}
					data_header.set(dataHeaderByte);
					protocolData = new ProtocolData();
					PcapDataHeader dataHeader = parseDataHeader(data_header.get());
                     JSONObject jsonObject=new JSONObject();
                     StringBuilder pcapHeader=new StringBuilder();
                     pcapHeader.append("Frame 1: ").append(dataHeader.getLen())
							 .append(" bytes on wire, ")
							 .append(dataHeader.getCaplen())
							 .append(" bytes captured");
                     jsonObject.put(pcapHeader.toString(),dataHeader);
                     byte[] contentByte=new byte[dataHeader.getCaplen()];
//					LogUtils.printObj("content.length", content.length);
					m = fis.read(contentByte);
					if(m==0) {
						break;
					}
					content.set(contentByte);
                    PcapDataFrame pcapDataFrame=readPcapDataFrame(content.get());
                    String pcapFrame="Ethernet II, Src: "+pcapDataFrame.getSrcMac()+" ("+pcapDataFrame.getSrcMac()+"), Dst: "+pcapDataFrame.getDesMac()+" ("+pcapDataFrame.getSrcMac()+")";
					jsonObject.put(pcapFrame,readPcapDataFrame(content.get()));
					IPHeader ipHeader=readIPHeader(content.get());

					if (ipHeader != null) {

						jsonObject.put("Internet Protocol, Src: "+protocolData.getSrcIP()+" ("+protocolData.getSrcIP()+"), Dst: "+protocolData.getDesIP()+" ("+protocolData.getDesIP()+")",ipHeader);
						String protocol = ipHeader.getProto() + "";
						if (ProtocolType.TCP.getType().equals(protocol)) {
							TCPHeader tcpHead= (TCPHeader) parseContent(ipHeader);
							StringBuilder tcp=new StringBuilder();
							tcp.append("Ⅳ,Transmission Control Protocol,Src Port:").append(tcpHead.getSrcPort())
									.append(", Dst port:").append(tcpHead.getDstPort())
									.append(", Seq:").append(tcpHead.getSeqNum())
									.append(", Ack:").append(tcpHead.getAckNum())
									.append(", Len:").append(tcpHead.getHeaderLen());
							StringBuilder tcpProtocol=new StringBuilder();
							tcpProtocol.append("Src Port:").append(tcpHead.getSrcPort())
									.append(", Dst port:").append(tcpHead.getDstPort())
									.append(", Seq:").append(tcpHead.getSeqNum())
									.append(", Ack:").append(tcpHead.getAckNum())
									.append(", Len:").append(tcpHead.getHeaderLen());
                           protocolData.setInfo(tcpProtocol.toString());
							jsonObject.put("Data",Optional.ofNullable(tcpHead.getData()).orElse("无"));
							if(tcpHead.getData()!=null){
								String[] tcps=tcpHead.getData().split(" ");
								if(tcps.length>2) {
									if (tcps[2].contains("HTTP")) {
										protocolData.setProtocolType("HTTP");
									}
								}
							}
							tcpHead.setData(null);
							jsonObject.put(tcp.toString(),tcpHead);

						} else if (ProtocolType.UDP.getType().equals(protocol)) {
							UDPHeader udpHead= (UDPHeader) parseContent(ipHeader);
							StringBuilder udp=new StringBuilder();
							udp.append("Ⅳ,User Datagram Protocol,Src Port:").append(udpHead.getSrcPort())
									.append(", Dst port:").append(udpHead.getDstPort());

							StringBuilder udpProtocol=new StringBuilder();
							udpProtocol.append("Src Port:").append(udpHead.getSrcPort())
									.append(", Dst port:").append(udpHead.getDstPort());
							protocolData.setInfo(udpProtocol.toString());

							jsonObject.put("Data",Optional.ofNullable(udpHead.getData()).orElse("无"));
							if(udpHead.getData()!=null){
								String[] tcps=udpHead.getData().split(" ");
								if(tcps.length>2) {
									if (tcps[2].contains("HTTP")) {
										protocolData.setProtocolType("HTTP");
									}
								}
							}
							udpHead.setData(null);
							jsonObject.put(udp.toString(),udpHead);
						} else {

							ICMPHeader icmpHeader= (ICMPHeader) parseContent(ipHeader);
							protocolData.setInfo(typeCode.get(icmpHeader.getIcmpType()).get(icmpHeader.getCode()));

							jsonObject.put("Data",Optional.ofNullable(icmpHeader.getData()).orElse("无"));
							icmpHeader.setData(null);
							jsonObject.put("Ⅳ,Internet Control Message Protocol",icmpHeader);

						}




					}
                     jsonObject.put("protocolData",protocolData);
				  	list.add(jsonObject);


				}


			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			FileUtils.closeStream(fis, null);
		}

		return list;
	}


	public static PcapFileHeader parseFileHeader(byte[] file_header) throws IOException {

		PcapFileHeader fileHeader = new PcapFileHeader();
		byte[] buff_4 = new byte[4];
		byte[] buff_2 = new byte[2];

		int offset = 0;
		for (int i = 0; i < 4; i ++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int magic = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setMagic(magic);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = file_header[i + offset];
		}
		offset += 2;
		short magorVersion = DataUtils.byteArrayToShort(buff_2);
		fileHeader.setMagorVersion(magorVersion);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = file_header[i + offset];
		}
		offset += 2;
		short minorVersion = DataUtils.byteArrayToShort(buff_2);
		fileHeader.setMinorVersion(minorVersion);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int timezone = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setTimezone(timezone);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int sigflags = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setSigflags(sigflags);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int snaplen = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setSnaplen(snaplen);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int linktype = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setLinktype(linktype);

//		LogUtils.printObjInfo(fileHeader);

		return fileHeader;
	}


	public static  PcapDataHeader parseDataHeader(byte[] data_header){
		byte[] buff_4 = new byte[4];
		PcapDataHeader dataHeader = new PcapDataHeader();
		int offset = 0;
		for (int i = 0; i < 4; i ++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;
		int timeS = DataUtils.byteArrayToIntFlip(buff_4,0);
		dataHeader.setTimeS(timeS);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;
		int timeMs = DataUtils.byteArrayToIntFlip(buff_4,0);
		dataHeader.setTimeMs(timeMs);
        protocolData.setTimeS(timeS);
		protocolData.setTimeMs(timeMs);
		for (int i = 0; i < 4; i ++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;

		DataUtils.reverseByteArray(buff_4);
		int caplen = DataUtils.byteArrayToInt(buff_4);
		dataHeader.setCaplen(caplen);


		for (int i = 0; i < 4; i ++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;
		//		int len = DataUtils.byteArrayToInt(buff_4);
		DataUtils.reverseByteArray(buff_4);
		int len = DataUtils.byteArrayToInt(buff_4);
		dataHeader.setLen(len);


		return dataHeader;
	}


	private static Object parseContent(IPHeader ipHeader) {

		int offset = 14;
		offset += 20;


		String protocol = ipHeader.getProto() + "";
		if (ProtocolType.TCP.getType().equals(protocol)) {
			protocolData.setProtocolType("TCP");
			return readTCPHeader(content.get(), offset);
		} else if (ProtocolType.UDP.getType().equals(protocol)) {
			protocolData.setProtocolType("UDP");
			return readUDPHeader(content.get(), offset);
		} else {
         	protocolData.setProtocolType("ICMP");
			return readICMPHeader(content.get(), offset);
		}


	}

	private static TCPHeader readTCPHeader(byte[] content, int offset) {
		byte[] buff_2 = new byte[2];
		byte[] buff_4 = new byte[4];

		TCPHeader tcp = new TCPHeader();

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
//			LogUtils.printByteToBinaryStr("TCP: buff_2[" + i + "]", buff_2[i]);
		}
		offset += 2;									// offset = 36

		String srcPort = DataUtils.binary(buff_2,10);
		tcp.setSrcPort(srcPort);


		protocolData.setSrcPort(srcPort);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 38
		String dstPort = DataUtils.binary(buff_2,10);
		tcp.setDstPort(dstPort);

		/*String desPort = validateData(dstPort);*/
		protocolData.setDesPort(dstPort);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 42
		int seqNum = DataUtils.byteArrayToInt(buff_4);
		tcp.setSeqNum(seqNum);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 46
		int ackNum = DataUtils.byteArrayToInt(buff_4);
		tcp.setAckNum(ackNum);

		byte headerLen = content[offset ++];			// offset = 47
		//tcp.setHeaderLen(DataUtils.byteToHexString(headerLen));
		tcp.setHeaderLen("32 bytes");

		byte flags = content[offset ++];				// offset = 48
		tcp.setFlags("0x"+DataUtils.byteToHexString(flags));

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 50
		short window = DataUtils.byteArrayToShort(buff_2);
		tcp.setWindow(window);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 52
		String checkSum = DataUtils.binary(buff_2,16);
		tcp.setCheckSum("0x"+checkSum);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 54
		short urgentPointer = DataUtils.byteArrayToShort(buff_2);
		tcp.setUrgentPointer(urgentPointer);
         offset+=12;
//		LogUtils.printObj("tcp.offset", offset);
		data_offset.set(offset);
//		LogUtils.printObjInfo(tcp);
		int data_size = content.length - data_offset.get();
//
        if(data_size>0){
		byte[] dataContent=new byte[data_size];
		for (int i = 0; i < data_size; i ++) {
			dataContent[i] = content[i + offset];
		}
		data_content.set(dataContent);
		tcp.setData(new String(dataContent));
        }
		return tcp;
	}

	private static UDPHeader readUDPHeader(byte[] content, int offset) {
		byte[] buff_2 = new byte[2];

		UDPHeader udp = new UDPHeader();
		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
//			LogUtils.printByteToBinaryStr("UDP: buff_2[" + i + "]", buff_2[i]);
		}
		offset += 2;									// offset = 36
		short srcPort = DataUtils.byteArrayToShort(buff_2);
		udp.setSrcPort(srcPort);

		String sourcePort = validateData(srcPort);
		protocolData.setSrcPort(sourcePort);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 38
		short dstPort = DataUtils.byteArrayToShort(buff_2);
		udp.setDstPort(dstPort);

		String desPort = validateData(dstPort);
		protocolData.setDesPort(desPort);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 40
		short length = DataUtils.byteArrayToShort(buff_2);
		udp.setLength(length);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 42
		short checkSum = DataUtils.byteArrayToShort(buff_2);
		udp.setCheckSum(checkSum);

		data_offset.set( offset);
		int data_size = content.length - data_offset.get();
		byte[] dataContent=new byte[data_size];
		for (int i = 0; i < data_size; i ++) {
			dataContent[i] = content[i + data_offset.get()];
		}
		data_content.set(dataContent);
		udp.setData(new String(dataContent));
		return udp;
	}

	private static ICMPHeader readICMPHeader(byte[] content, int offset) {

		CommonHeadAnalyze hd = new CommonHeadAnalyze(content);

		int icmpType = ByteUtil.byteToInt(content[offset]);
		int code = ByteUtil.byteToInt(content[offset+1]);
		String checkSum = "0x"+ByteUtil.byteToHexString(content[offset+2])+ByteUtil.byteToHexString(content[offset+3]);
		int identifierBE = ByteUtil.unionByte(content[offset+4], content[offset+5]);
		byte b2=0;
		int identifierLE = ByteUtil.unionByte(content[offset+5], b2);
		int seqNumBE = ByteUtil.unionByte(content[offset+6], content[offset+7]);
		int seqNumLE = ByteUtil.unionByte(content[offset+7], b2);
		 data_offset.set(offset+7);

		int data_size = content.length - data_offset.get();
		byte[] dataContent=new byte[data_size];
		for (int i = 0; i < data_size; i ++) {
			dataContent[i] = content[i + data_offset.get()];
		}
		data_content.set(dataContent);
		return new ICMPHeader(icmpType,code,checkSum,identifierBE,identifierLE,seqNumBE,seqNumLE,new String(dataContent));
	}


	public static PcapDataFrame readPcapDataFrame(byte[] content) {
		PcapDataFrame dataFrame = new PcapDataFrame();
		int offset = 0;
		byte[] dst=new byte[6];
		for (int i = 0; i < 6; i ++) {
			byte t=content[offset];
			dst[i] = t;
			offset++;
		}
		byte[] src=new byte[6];
		for (int i = 0; i < 6; i ++) {
			src[i] = content[offset];
			offset++;
		}
		byte[] buff_2 = new byte[2];
		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[offset];
			offset++;
		}
		String dstString=DataUtils.toHexString(dst);
		String srcString=DataUtils.toHexString(src);
		String frameType = "0x"+DataUtils.toHexString(buff_2);
		dataFrame.setFrameType(frameType);
		dataFrame.setDesMac(dstString);
		dataFrame.setSrcMac(srcString);
		return dataFrame;
//		LogUtils.printObjInfo(dataFrame);
	}

	private static IPHeader readIPHeader(byte[] content) {
		int offset = 15;
		IPHeader ip = new IPHeader();
		ip.setVersion("4");
		ip.setHdr_len("20 bytes");
         byte dsfield=content[offset++];
		String dsfieldString=DataUtils.byteToHexString(dsfield);
		ip.setDsfield("0x"+dsfieldString);
		byte[] buff_2 = new byte[2];
		byte[] buff_4 = new byte[4];
		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[offset];
			offset++;
		}
		short len = DataUtils.byteArrayToShort(buff_2);
         ip.setLen(len);
		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[offset];
			offset++;
		}
		short id = DataUtils.byteArrayToShort(buff_2);
		ip.setId(id);

		ip.setFlags("0x02");
        ip.setFrag_offset(0);
        offset+=2;
		byte ttl = content[offset ++];
		ip.setTtl(ttl);
		byte protocol = content[offset ++];				// offset = 24
		ip.setProto(protocol);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 26
		short checkSum = DataUtils.byteArrayToShort(buff_2);
		ip.setChecksum(checkSum);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 30
		int srcIP = DataUtils.byteArrayToInt(buff_4);
		ip.setSrc(srcIP);


		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			builder.append((int) (buff_4[i] & 0xff));
			builder.append(".");
		}
		builder.deleteCharAt(builder.length() - 1);
		String sourceIP = builder.toString();
		protocolData.setSrcIP(sourceIP);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 34
		int dstIP = DataUtils.byteArrayToInt(buff_4);
		ip.setDst(dstIP);

		//  DestinationIP
		builder = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			builder.append((int) (buff_4[i] & 0xff));
			builder.append(".");
		}
		builder.deleteCharAt(builder.length() - 1);
		String destinationIP = builder.toString();
		protocolData.setDesIP(destinationIP);

		return ip;
	}






	private static String validateData (int data) {
		String rs = data + "";
		if (data < 0) {
			String binaryPort = Integer.toBinaryString(data);
			rs = DataUtils.binaryToDecimal(binaryPort) + "";
		}

		return rs;
	}
	
}
