package crypto.cipher;

import java.util.Arrays;

public class ECB implements CipherAlgo {
	private CipherAlgo algo;		//algorithme utilisé dans le schéma ECB
	//private int block_size;			//la taille du block : peut changer
	public static final int BLOCKSIZE = 16;
	
	public ECB(CipherAlgo algo, int block_size) {
		this.algo = algo;
		//this.block_size = block_size;
	}
	
	public static boolean detect_ecb(byte[]cipherbytes) {
		int		 nb_blocks		= cipherbytes.length/BLOCKSIZE;
		byte[][] cipher_blocks 	= new byte[nb_blocks][BLOCKSIZE];
		int k = 0;
		//positionner les octets de message chiffré dans une matrice
		//un bloc par ligne
		for(int i = 0; i < nb_blocks; i++){
			for(int j = 0; j < BLOCKSIZE; j++){
				cipher_blocks[i][j] = cipherbytes[k];
				k++;
			}
		}
		//comparer les ligne deux à deux pour verifier les répétitions
		for(int i = 0; i < nb_blocks; i++) {
			for(int j = 0; j < nb_blocks; j++) {
				if(Arrays.equals(cipher_blocks[i], cipher_blocks[j]) && i != j){
					return true;
				}
			}
		}
		return false;
	}
	//ajouter le contenu tableau "from" à la position
	//correspondant au block numéro "block_num" du tableau "to"
	public void add_block_result(byte[] to, byte[]from, int block_num) {
		int init_pos = block_num * BLOCKSIZE;
		for(int i = 0 ; i < BLOCKSIZE; i++) {
			to[init_pos + i] = from[i];  
		}
	}
	@Override
	public byte[] encrypt(byte[] plaintext_bytes) {
		int nb_blocks = plaintext_bytes.length / BLOCKSIZE;
		byte[] plaintext_block, output_bytes;
		byte[] result = new byte[nb_blocks * BLOCKSIZE];
		for(int i = 0; i < nb_blocks; i++) {
			//prendre le bloc i
			plaintext_block 	=  Arrays.copyOfRange(plaintext_bytes, i * BLOCKSIZE, (i+1)*BLOCKSIZE);
			//chiffrer ce bloc
			output_bytes		=  algo.encrypt(plaintext_block);
			//concatener au resultat
			add_block_result(result, output_bytes, i);
		}
		return result;
	}

	@Override
	public byte[] decrypt(byte[] ciphertext_bytes) {
		int nb_blocks = ciphertext_bytes.length / BLOCKSIZE;
		byte[] ciphertext_block, output_bytes;
		byte[] result = new byte[nb_blocks * BLOCKSIZE];
		for(int i = 0; i < nb_blocks; i++) {
			//prendre le block i
			ciphertext_block =  Arrays.copyOfRange(ciphertext_bytes, i * BLOCKSIZE, (i+1)*BLOCKSIZE);
			//chiffrer ce bloc
			output_bytes = algo.decrypt(ciphertext_block);
			//concatener au resultat
			add_block_result(result, output_bytes, i);
		}
		return result;
	}
}
