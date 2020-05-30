package crypto.cipher;

import java.util.Arrays;

public class CBC implements CipherAlgo {
	
	private CipherAlgo algo;
	private byte[]	init_vector;
	//private int		block_size;
	public static final int BLOCKSIZE = 16;
	
	public CBC(CipherAlgo algo, int block_size) {
		this.algo = algo;
		//this.block_size = block_size;
		this.init_vector = new byte[BLOCKSIZE];
		for(int i = 0; i < BLOCKSIZE;  i++) {
			init_vector[i] = (byte) 0;
		}
	}
	
	public void set_init_vector(byte[] vect) {
		init_vector = vect;
	}
	//ajouter le contenu tableau "from" à la position
	//correspondant au block numéro "block_num" du tableau "to"
	public void add_block_result(byte[] to, byte[]from, int block_num) {
		int ref = block_num * BLOCKSIZE;
		for(int i = 0 ; i < BLOCKSIZE; i++) {
			to[ref + i] = from[i];  
		}
	}

	@Override
	public byte[] encrypt(byte[] plaintext_bytes) {
		int nb_blocks = plaintext_bytes.length / BLOCKSIZE;
		byte[] plainttext_block, output_bytes = init_vector;
		byte[] result = new byte[nb_blocks * BLOCKSIZE];
		for(int i = 0; i < nb_blocks; i++) {
			//prendre le bloc i
			plainttext_block =  Arrays.copyOfRange(plaintext_bytes, i * BLOCKSIZE, (i+1) * BLOCKSIZE);
			//faire un xor entre le bloc i du message actuel et le block chiffré précédent
			plainttext_block =  FixedXor.encode(plainttext_block, output_bytes);
			//chiffré le dernier résultat
			output_bytes     =  algo.encrypt(plainttext_block);
			//concaténer au résultat
			add_block_result(result, output_bytes, i);
		}
		return result;
	}

	@Override
	public byte[] decrypt(byte[] ciphertext_bytes) {
		int nb_blocks = ciphertext_bytes.length / BLOCKSIZE;
		byte[] ciphertext_block_current, ciphertext_block_prev, xor_input, plaintext_bytes;
		byte[] result = new byte[nb_blocks * BLOCKSIZE];
		for(int i = nb_blocks - 1; i >= 0; i--) {
			//prendre le bloc i
			ciphertext_block_current =  Arrays.copyOfRange(ciphertext_bytes, i * BLOCKSIZE, (i+1) * BLOCKSIZE);
			if(i == 0) {
				ciphertext_block_prev    =  init_vector;
			}else {
				ciphertext_block_prev    =  Arrays.copyOfRange(ciphertext_bytes, (i-1) * BLOCKSIZE, (i)*BLOCKSIZE);
			}
			//dechiffrer le bloc chiffré i
			xor_input	    =  algo.decrypt(ciphertext_block_current);
			//faire un xor avec le chiffrement précédent pour avoir le block i en clair
			plaintext_bytes	=  FixedXor.encode(xor_input, ciphertext_block_prev);
			//concatener au résultat
			add_block_result(result, plaintext_bytes, i);
		}
		return result;
	}
}
