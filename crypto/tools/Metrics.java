package crypto.tools;

import crypto.cipher.FixedXor;

public class Metrics {
	//https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
	private static final double[] ALPHA_FREQ_ENGLISH ={
			8.167, //a
			1.492, //b
			2.782, //c
			4.253, //d
			12.702,//e
			2.228, //f
			2.015,
			6.094,
			6.966,
			0.153,
			0.772,
			4.025,
			2.406,
			6.749,
			7.507,
			1.929,
			0.095,
			5.987,
			6.327,
			9.056,
			2.758,
			0.978,
			2.360,
			0.150,
			1.974, //y
			0.074  //z
			//others = 0
		};
	//doit etre superieur au max alphabet donc e
	private static final double   SPACE_FREQ_ENGLISH = 20;
	
	public static double english_frequency_score(String str) {
		double valeur = 0;
		for(byte b : str.toLowerCase().getBytes()) {
			if(b >= 'a' && b <= 'z')
				valeur+=ALPHA_FREQ_ENGLISH[b-'a'];
			else if(b == ' ') {
				valeur+=SPACE_FREQ_ENGLISH;
			}
		}
		return valeur;
	}
	
	public static int hamming_distance(byte[] bytes1, byte[] bytes2) {
		if(bytes1.length != bytes2.length) {
			return -1;
		}
		int distance = 0;
		byte[] tmp = FixedXor.encode(bytes1, bytes2);
		for(int i = 0; i < tmp.length; i++) {
			for(int j = 0; j < 8; j++) {
				if( ( (tmp[i] >> j) & 1) == 1) {
					distance++;
				}
			}	
		}
		return distance;
	}
}
