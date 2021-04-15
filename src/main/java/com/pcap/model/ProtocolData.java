package com.pcap.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class ProtocolData {

	String srcIP;
	String desIP;
	
	String srcPort;
	String desPort;
	Integer timeS;
	Integer timeMs;
	String info;
	String protocolType ;



}
