package com.pcap.model;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class UDPHeader {
	
	private short srcPort;
	private short dstPort;
	private short length;
	private short checkSum;

	private String data;
	
}
