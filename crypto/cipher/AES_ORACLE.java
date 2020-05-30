package crypto.cipher;

import java.util.Random;

import crypto.tools.HexString;

public class AES_ORACLE extends AES {

	public AES_ORACLE() {
		super();
		new Random().nextBytes(key_bytes);
	}
	
	public AES_ORACLE(String key_str) {
		super(key_str);
	}
    
	public void add_block_result(byte[] to, byte[]from, int block_pos) {
		int init_pos = block_pos * BLOCKSIZE;
		for(int i = 0 ; i < BLOCKSIZE; i++) {
			to[init_pos + i] = from[i];  
		}
	}
	
	public byte[] oracle_encrypt(byte[] input_bytes) {
		
		System.out.println("Random generated Key in hex : " + HexString.fromBytes(key_bytes));
	
		int a = new Random().nextInt(6)/*Int 0 -> 5*/ + 5;
		int b = new Random().nextInt(6) + 5;
		int taille = input_bytes.length + a + b;
		
		byte[] plaintext_bytes = new byte[taille];
		
		System.out.println("Input plaintext in hex          : " + HexString.fromBytes(input_bytes));
		
		for(int i = 0; i < taille; i++) {
			if(i < a) {
				//entre 0 et a (exclut) remplir avec des nombre aléatoire compris entre 0->255
				plaintext_bytes[i] = (byte)new Random().nextInt(256);
			}else if (i < (input_bytes.length + a) ) {
				//remplir avec l'entrée après la position a
				plaintext_bytes[i] = input_bytes[i-a];
			}else {
				//les derniers b octets : remplir avec des nombre aléatoire compris entre 0->255
				plaintext_bytes[i] = (byte)new Random().nextInt(256);
			}
		}
		System.out.println("modified plaintext in hex       : " + HexString.fromBytes(plaintext_bytes));
		plaintext_bytes = PKCS7.padding(plaintext_bytes, BLOCKSIZE);
		System.out.println("modified pkcs7 plaintext in hex : " + HexString.fromBytes(plaintext_bytes));
		//instancier un CBC avec un vecteur initial aléatoire
		CBC cbc = new CBC(this, BLOCKSIZE);
		byte[] init_vect = new byte[BLOCKSIZE];
		new Random().nextBytes(init_vect);
		cbc.set_init_vector(init_vect);
		//instancier un ECB
		ECB ecb = new ECB(this, BLOCKSIZE);
		
		//alloué de l'espace pour le resultat
		int nb_blocks = plaintext_bytes.length / BLOCKSIZE;
		byte[] result = new byte[nb_blocks * BLOCKSIZE];

		//generer un nombre aléatoire 0 ou 1 pour le choix de l'algorithme
		int algo_number = new Random().nextInt(2);
			
		if( algo_number  == 0) {
			System.out.println("Used mode : AES Oracle ECB");
			result = ecb.encrypt(plaintext_bytes);
		}else {
			System.out.println("Used mode : AES Oracle CBC, IV: "+ HexString.fromBytes(init_vect));
			result = cbc.encrypt(plaintext_bytes);
		}
		
		System.out.println("Oracle encryption result in hex : " + HexString.fromBytes(result));
		
		return result;
	}
	
	public byte[] oracle_ecb(byte[] input_bytes) {
		
		byte[] plaintext_bytes = input_bytes;
		
		ECB ecb = new ECB(this, BLOCKSIZE);

		plaintext_bytes = PKCS7.padding(plaintext_bytes, BLOCKSIZE);
				
		int nb_blocks = plaintext_bytes.length / BLOCKSIZE;
		//apres le padding : la taille de plaintext est un multiple de BLOCKSIZE		
		byte[] result = new byte[nb_blocks * BLOCKSIZE];
		
		result = ecb.encrypt(plaintext_bytes);

		return result;
	}
}
   