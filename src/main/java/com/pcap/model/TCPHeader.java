package com.pcap.model;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class TCPHeader {

	//源端口
	private String srcPort;

	//目的端口
	private String dstPort;

	//序号
	private int seqNum;

	//确认号
	private int ackNum;

	//数据报头的长度(4 bit) + 保留(4 bit)
	private String headerLen;
	//标识TCP不同的控制消息
	private String flags;

	//窗口大小
	private short window;

	//校验和
	private String checkSum;

	//紧急指针
	private short urgentPointer;
	private String data;



	

}
