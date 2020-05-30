package crypto.cipher;

import crypto.tools.Metrics;

public class SingleByteXor {
	//fonction d'encodage : bytes pour le message en clair, key pour la clé
	public static byte[] encode(byte[] bytes, byte key) {
		byte[] result_bytes = new byte[bytes.length];
		
		for(int i = 0; i < bytes.length; i++) {
			result_bytes[i] = (byte)(bytes[i] ^ key);
		}
		return result_bytes;
	}
	//la fonction encode est décode sont les mêmes : propriete de XOR
	//bytes pour le message chiffré
	public static byte[] decode(byte[] bytes, byte key) {
		return encode(bytes, key);
	}
	//cherche la clé de chiffrement:
	public static byte find_key(byte[] bytes) {
		byte[] decoded_bytes;
		double score_max = -1;
		byte key = 0; //null char
		for(int i = 0; i < 256; i++)
		{
			decoded_bytes = decode(bytes, (byte)i);
			//bytes to string
			String englishDecoded = new String(decoded_bytes);
			double score = Metrics.english_frequency_score(englishDecoded);
			if(score > score_max) {
				score_max = score;
				key = (byte)i;	
			}
		}
		return key;
	}
}
