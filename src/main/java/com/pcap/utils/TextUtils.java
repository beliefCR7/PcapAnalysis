package com.pcap.utils;

public class TextUtils {
	
	private TextUtils () {}
	

	public static boolean isEmpty (String str) {
		if (str == null || str.length() < 0) {
			return true;
		} else {
			return false;
		}
	}
	
}
