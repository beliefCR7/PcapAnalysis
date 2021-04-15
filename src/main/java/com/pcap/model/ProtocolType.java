package com.pcap.model;


public enum ProtocolType {
	
	OTHER("0"),
	TCP("6"),
	UDP("17"),
	ICMP("1");

	private String type;
	
	public String getType() {
		return type;
	}
	
	public void setType(String type) {
		this.type = type;
	}
	
	private ProtocolType(String type) {
		this.type = type;
	}
	
}
