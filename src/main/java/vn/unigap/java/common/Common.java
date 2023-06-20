package vn.unigap.java.common;

import java.util.UUID;

public class Common {
	public static String uuid() {
		return UUID.randomUUID().toString();
	}

	public static String subString(String str, int len) {
		if (str == null) return null;
		return str.substring(0, Math.min(len, str.length()));
	}
}
