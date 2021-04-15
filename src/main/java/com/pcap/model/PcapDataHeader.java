package com.pcap.model;


import com.pcap.utils.DataUtils;

public class PcapDataHeader {
	

	private int timeS;	

	private int timeMs;						

	private int caplen;

	private int len;						
	
	public int getTimeS() {
		return timeS;
	}

	public void setTimeS(int timeS) {
		this.timeS = timeS;
	}

	public int getTimeMs() {
		return timeMs;
	}

	public void setTimeMs(int timeMs) {
		this.timeMs = timeMs;
	}

	public int getCaplen() {
		return caplen;
	}

	public void setCaplen(int caplen) {
		this.caplen = caplen;
	}

	public int getLen() {
		return len;
	}

	public void setLen(int len) {
		this.len = len;
	}

	public PcapDataHeader() {}
	
	@Override
	public String toString() {
		return "PcapDataHeader [timeS=" +  DataUtils.intToHexString(timeS)
				+ ", timeMs=" +  DataUtils.intToHexString(timeMs)
				+ ", caplen=" +  caplen
				+ ", len=" +  len
				+ "]";
	}

}
