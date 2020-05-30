package crypto.cipher;

public class RepeatedXOR {
	//fonction d'encodage : bytes pour le message en clair, key pour la clé
	public static byte[] encode(byte[] bytes, byte[] key) {
		byte[] result_bytes = new byte[bytes.length];
		for(int i = 0; i < bytes.length; i++) {
			result_bytes[i] = (byte) (bytes[i] ^ key[i % key.length]);
		}
		return result_bytes;
	}
	//la fonction encode est décode sont les mêmes : propriete de XOR
	//bytes pour le message chiffré
	public static byte[] decode(byte[] bytes, byte[] key) {
		return encode(bytes, key);
	}
}
