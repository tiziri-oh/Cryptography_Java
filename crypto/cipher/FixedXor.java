package crypto.cipher;

public class FixedXor {
	//fonction d'encodage : bytes pour le message en clair, key pour la clé
	public static byte[] encode(byte[] bytes, byte[] key) {
		if(bytes.length != key.length) {
			return null;
		}
		byte[] result_bytes = new byte[bytes.length];
		
		for(int i = 0; i < bytes.length; i++) {
			result_bytes[i] = (byte)(bytes[i] ^ key[i]);
		}
		return result_bytes;
	}
	//la fonction encode est décode sont les mêmes : propriete de XOR
	//bytes pour le message chiffré
	public static byte[] decode(byte[] bytes, byte[] key) {
		return encode(bytes,key);
	}
	
}
