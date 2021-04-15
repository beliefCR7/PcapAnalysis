package com.pcap.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ICMPHeader {
	protected int icmpType;
	protected int code;
	protected String checkSum;
	protected int identifierBE;
	protected int identifierLE;
	protected int seqNumBE;
	protected int seqNumLE;
    protected  String data;


}
