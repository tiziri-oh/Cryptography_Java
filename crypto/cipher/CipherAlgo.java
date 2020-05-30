package crypto.cipher;

public interface CipherAlgo {
	public byte[] encrypt(byte[] plaintext_bytes);	
	public byte[] decrypt(byte[] ciphertext_bytes);
}
