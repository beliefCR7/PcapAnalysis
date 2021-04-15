package com.pcap.model;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class IPHeader {
	private String version;
	private String hdr_len;
	private String dsfield;
	private short len;
	private short id;
	private String flags;
	private int frag_offset;
	private short ttl;
	private short proto;
	private short checksum;
	private int src;
	private int dst;
}
