package crypto.tools;

import java.util.Base64;

public class HexString {
	
	
	//Question one
	public static String toBase64( String hexStr) {
		byte[] hexBytes = new byte[hexStr.length() / 2];
		for (int i = 0; i < hexBytes.length; i++) {
			   int index = i * 2;
			   int integer = Integer.parseInt(hexStr.substring(index, index + 2), 16);
			   hexBytes[i] = (byte) integer;
		}
		 return Base64.getEncoder().encodeToString(hexBytes); 
	}
	
	public static String toString(String hexStr) {
		//call constructor String arg byte[]
		return new String(toBytes(hexStr));
	}
	
	public static byte[] toBytes(String hexStr) {
		byte[] hexBytes = new byte[hexStr.length() / 2];
		for (int i = 0; i < hexBytes.length; i++) {
			   int index = i * 2;
			   int integer = Integer.parseInt(hexStr.substring(index, index + 2), 16);
			   hexBytes[i] = (byte) integer;
		}
		return hexBytes;
	}

	public static String fromBytes(byte[] bytes) {
		String result_hex_string = "";
		for (byte b : bytes) {
			result_hex_string += String.format("%02x", b);
        }
		return result_hex_string;
	}
	
}
