package com.pcap.model;

import java.util.List;


public class PcapStruct {

	private PcapFileHeader fileHeader;
	private List<PcapDataHeader> dataHeaders;
	
	public PcapFileHeader getFileHeader() {
		return fileHeader;
	}
	public void setFileHeader(PcapFileHeader fileHeader) {
		this.fileHeader = fileHeader;
	}
	public List<PcapDataHeader> getDataHeaders() {
		return dataHeaders;
	}
	public void setDataHeaders(List<PcapDataHeader> dataHeaders) {
		this.dataHeaders = dataHeaders;
	}
	
	public PcapStruct() {}
	
	
}
