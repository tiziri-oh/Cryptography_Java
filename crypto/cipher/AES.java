package crypto.cipher;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AES implements CipherAlgo {
	
    protected static final String CIPHER_MODE  = "AES/ECB/NoPadding";
    protected static final int    KEY_SIZE     = 16;
    protected static final int    BLOCKSIZE    = 16;
    protected byte[] key_bytes;

	public AES() {
		this.key_bytes = new byte[KEY_SIZE];
	}
    
	public AES(String key_str) {
		this.key_bytes = Arrays.copyOf(key_str.getBytes(), KEY_SIZE);;
	}
	
	public void set_key(byte[] key) {
		this.key_bytes = key;
	}
	
    public byte[] decrypt(byte[] content) {
        try {
            //créer une clé de type AES (compatible avec la class Cipher de Java) avec notre clé
        	SecretKeySpec key = new SecretKeySpec(key_bytes, "AES");
            //appeler une instance de Cipher de type AES
            Cipher cipher = Cipher.getInstance(CIPHER_MODE);
            //initialisé l'instance avec la clé et le mode chiffrement ou déchiffrement
            cipher.init(Cipher.DECRYPT_MODE, key);
            //executer le chiffrement
            byte[] result = cipher.doFinal(content);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public byte[] encrypt(byte[] content) {
        try {
            //créer une clé de type AES (compatible avec la class Cipher de Java) avec notre clé
            SecretKeySpec key = new SecretKeySpec(key_bytes, "AES");
            //appeler une instance de Cipher de type AES
            Cipher cipher = Cipher.getInstance(CIPHER_MODE);
            //initialisé l'instance avec la clé et le mode chiffrement ou déchiffrement
            cipher.init(Cipher.ENCRYPT_MODE, key);
            //executer le chiffrement
            byte[] result = cipher.doFinal(content);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}