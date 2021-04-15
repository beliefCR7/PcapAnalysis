package com.pcap.model;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class PcapDataFrame {
	

	private String desMac;
	

	private String srcMac;
	

	private String frameType;


	
}
