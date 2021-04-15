package com.pcap.utils;

import java.awt.*;


public class WindowUtils {

	private static final Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
	
	private WindowUtils () {}
	

	public static int getScreenWidth () {
		return screenSize.width;
	}


	public static int getScreenHeight () {
		return screenSize.height;
	}
	
}
