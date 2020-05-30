package crypto;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Base64;

import crypto.cipher.AES;
import crypto.cipher.AES_ORACLE;
import crypto.cipher.CBC;
import crypto.cipher.ECB;
import crypto.cipher.FixedXor;
import crypto.cipher.PKCS7;
import crypto.cipher.RepeatedXOR;
import crypto.cipher.SingleByteXor;
import crypto.examples.CryptoExamples;
import crypto.tools.HexString;
import crypto.tools.Metrics;

public class Main {	

	public static void main(String[] args) {
		
		question1_1();end_question();
		question1_2();end_question();
		question1_3();end_question();
		question1_4();end_question();
		question1_5();end_question();
		question1_6();end_question();
		question1_7();end_question();
		question1_8();end_question();
		
		question2_1();end_question();
		question2_2();end_question();
		question2_3();end_question();
		question2_4();end_question();
	}
	
	private static final String Q1_1_HEXTOBASE64		= "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	
	private static final String Q1_2_FIXEDXOR_HEXSTR1	= "1c0111001f010100061a024b53535009181c";
	private static final String Q1_2_FIXEDXOR_HEXSTR2	= "686974207468652062756c6c277320657965";
	
	private static final String Q1_3_BYTEXOR_HEXSTR1	= "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
	
	private static final String Q1_4_FILENAME			= "detecting-singlechar-xor.txt";
	
	private static final String Q1_5_PLAINTEXT			= "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal";
	private static final String Q1_5_KEY				= "ICE";
	
	private static final String Q1_6_FILENAME			= "repeating-xor.txt";
	private static final int Q1_6_KEYSIZE_MIN 			= 2;
	private static final int Q1_6_KEYSIZE_MAX 			= 40;
	private static final String Q1_6_HAMMING_STR1 		= "this is a test";
	private static final String Q1_6_HAMMING_STR2 		= "wokka wokka!!!";
	
	private static final String Q1_7_KEY_STR			= "YELLOW SUBMARINE";
	private static final String Q1_7_FILENAME	   		= "aes-in-ecb.txt";
	
	private static final String Q1_8_FILENAME	   		= "detect-aes-ecb.txt";
	
	private static final String Q2_1_PKCS7_STR			= "YELLOW SUBMARINE";
	
	private static final String Q2_2_FILENAME			= "cbc-mode.txt";
	private static final String Q2_2_PKCS7_STR			= "YELLOW SUBMARINE";
	
	private static final String Q2_4_APPEND_STR			= "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
														+ "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
														+ "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
														+ "YnkK";
	
	public static void end_question() {
		System.out.println("################################################################################################");
	}
	
	public static void question1_1() {
		System.out.println("Question 1.1 : Convert hex to base64");
		System.out.println("Original: " + Q1_1_HEXTOBASE64 );
		System.out.println("Result  : " + HexString.toBase64(Q1_1_HEXTOBASE64));
	}
	
	public static void question1_2() {
		System.out.println("Question 1.2 : Fixed XOR");
		System.out.println("Original: " + Q1_2_FIXEDXOR_HEXSTR1 );
		System.out.println("Original: " + Q1_2_FIXEDXOR_HEXSTR2 );
		System.out.println("Result  : " + HexString.fromBytes(
											FixedXor.encode(
													HexString.toBytes(Q1_2_FIXEDXOR_HEXSTR1), 
													HexString.toBytes(Q1_2_FIXEDXOR_HEXSTR2)
											)
										));
	}
	
	public static void question1_3() {
		System.out.println("Question 1.3 : Single-byte XOR cipher");
		int key = SingleByteXor.find_key( HexString.toBytes(Q1_3_BYTEXOR_HEXSTR1) );
		byte[] decoded_byte = SingleByteXor.decode(HexString.toBytes(Q1_3_BYTEXOR_HEXSTR1), (byte)key);
		System.out.println("Found key using english word frequency metric is : " + (char) key );
		System.out.println("Decoded message using this key : " + new String(decoded_byte));
	}
	
	public static void question1_4() {
		System.out.println("Question 1.4 : Detect single-character XOR");
		String line = null;
		String plaintext = "";
		String ciphertext = "";
		int count = 1, line_num = 1;
		
		double score_max = -1;
		try {
			System.out.println("Read file : " + Q1_4_FILENAME);
			InputStream in =  CryptoExamples.getInputStream(Q1_4_FILENAME);
			BufferedReader input = new BufferedReader(new InputStreamReader(in,"UTF-8"));
			byte[] decoded_bytes;
			String english_text;
			while ((line = input.readLine()) != null) {
				byte key = SingleByteXor.find_key(HexString.toBytes(line));
				decoded_bytes = SingleByteXor.decode(HexString.toBytes(line), (byte)key);
				english_text  = new String(decoded_bytes);
				double score = Metrics.english_frequency_score(english_text);
				if(score > score_max) {
					line_num   = count;
					score_max  = score;
					ciphertext = line;
					plaintext  = english_text;
				}
				count++;
			}
			System.out.println("line "+ line_num + " (has maximum score), ciphertext:" + ciphertext);
			System.out.println("line "+ line_num + " (decoded message  ), plaintext :" + plaintext);
			input.close();
		}catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}
	
	public static void question1_5(){
		System.out.println("Question 1.5 : Implement repeating-key XOR");
		System.out.println("plaint text  : "+ Q1_5_PLAINTEXT);
		System.out.println("key          : "+ Q1_5_KEY);
		System.out.println("result       : "+ HexString.fromBytes( RepeatedXOR.encode(Q1_5_PLAINTEXT.getBytes(), Q1_5_KEY.getBytes() ) ) );		
	}
	
	public static void question1_6(){
		System.out.println("Question 1.6 : Break repeating-key XOR");
		int KEYSIZE;
		System.out.println("Text 1       : " + Q1_6_HAMMING_STR1);
		System.out.println("Text 2       : " + Q1_6_HAMMING_STR2);
		System.out.println("Test hamming distance: " + Metrics.hamming_distance(Q1_6_HAMMING_STR1.getBytes(), Q1_6_HAMMING_STR2.getBytes()));
		
		
		System.out.println("----- Break repeating-key XOR -----");
		System.out.println("----- Read file : " + Q1_6_FILENAME + " -----");
		byte[] ciphertextbytes = Base64.getDecoder().decode(CryptoExamples.getContent(Q1_6_FILENAME));
		double min = Q1_6_KEYSIZE_MAX * 8;
		int opt_keysize = 0;
		
		System.out.println("----- Getting minimum hamming distance from average of 4 sequences----- ");
		for(KEYSIZE = Q1_6_KEYSIZE_MIN; KEYSIZE <= Q1_6_KEYSIZE_MAX; KEYSIZE++) {
			byte[] first  = Arrays.copyOfRange(ciphertextbytes, 0 * KEYSIZE	, 1 * KEYSIZE);
			byte[] second = Arrays.copyOfRange(ciphertextbytes, 1 * KEYSIZE	, 2 * KEYSIZE);
			byte[] third  = Arrays.copyOfRange(ciphertextbytes, 2 * KEYSIZE	, 3 * KEYSIZE);
			byte[] fourth = Arrays.copyOfRange(ciphertextbytes, 3 * KEYSIZE	, 4 * KEYSIZE);
			double norm_dist = Metrics.hamming_distance(first, second) + Metrics.hamming_distance(first, third) 
							+  Metrics.hamming_distance(first, fourth) + Metrics.hamming_distance(second, third) 
							+  Metrics.hamming_distance(second,fourth) + Metrics.hamming_distance(third, fourth);
			norm_dist /= 6;
			norm_dist /= KEYSIZE;
			if(min > norm_dist) {
				min = norm_dist;
				opt_keysize = KEYSIZE;
			}			
		}
		System.out.println("----- Optimal value found for KEYSIZE: " + opt_keysize + " -----");

		//ABCDEFGHI   (par byte )
		//ABC,DEF,GHI (par bloc )
		//ICE,ICE,ICE (chaque bloc codé avec la même clé)
		int nb_blocks = ciphertextbytes.length / opt_keysize;
		byte[][] blocks = new byte[nb_blocks][opt_keysize];
		int k = 0;
		for(int i = 0; i < nb_blocks; i++) {
			for(int j = 0; j < opt_keysize; j++) {
				blocks[i][j] =  ciphertextbytes[k];
				k++;
			}
		}
		
		//ADG,BEH,CFI (transpose)
		//III,CCC,EEE (chaque bloc codé avec le même caractère)
		byte[][] blocks_transp = new byte[opt_keysize][nb_blocks];
		for(int i = 0; i < opt_keysize; i++) {
			for(int j = 0; j < nb_blocks; j++) {
				blocks_transp[i][j] =  blocks[j][i];
			}
		}
		byte[] key = new byte[opt_keysize];
		for(int i = 0; i < opt_keysize; i++) {
			key[i] = SingleByteXor.find_key(blocks_transp[i]);
		}
		
		System.out.println("The key found is   : " + new String(key));
		System.out.println("decrypted plaintext: " + new String(RepeatedXOR.decode(ciphertextbytes, key)));
		
	}
	
	public static void question1_7(){
		System.out.println("Question 1.7 : AES in ECB mode");
		byte[] ciphertext_bytes = Base64.getDecoder().decode(CryptoExamples.getContent(Q1_7_FILENAME));
		try {
			System.out.println("----- Create AES Instance using key : " + Q1_7_KEY_STR + " -----");
			AES aes = new AES(Q1_7_KEY_STR);
			System.out.println("----- Create ECB associated to ASE Instance -----");
			ECB aes_128_ebc = new ECB(aes, 16);
			System.out.println("----- Decrypt file : " + Q1_7_FILENAME + " -----");
			byte[] plaintext_bytes = aes_128_ebc.decrypt(ciphertext_bytes);
			System.out.println(new String(plaintext_bytes));
		} catch (Exception e) {
			e.getMessage();
		}
	}
	
	public static void question1_8(){
		System.out.println("Question 1.8 : Detect AES in ECB mode");
		InputStream in =  CryptoExamples.getInputStream(Q1_8_FILENAME);
		BufferedReader input;
		try {
			System.out.println("----- Read file : " + Q1_8_FILENAME + " -----");
			input = new BufferedReader(new InputStreamReader(in,"UTF-8"));
	 		String line = null;
	 		int line_num = 1;
			while ((line = input.readLine()) != null) {
				byte[] cipherbytes		= HexString.toBytes(line);				
				boolean found 			= ECB.detect_ecb(cipherbytes);
				if(found){
					System.out.println("ASE ECB line number: " + line_num + ", text: " + line);
				}
				line_num++;
			}
			input.close();
		} catch (Exception e) {
			e.getMessage();
		}		
	}
	
	public static void question2_1() {
		System.out.println("Question 2.1 : Implement PKCS#7 padding");
		byte[] pad_bytes = PKCS7.padding(Q2_1_PKCS7_STR.getBytes(), 20);
		System.out.println("Original         : " + Q2_1_PKCS7_STR);
		System.out.println("Original hex     : " + HexString.fromBytes(Q2_1_PKCS7_STR.getBytes()));
		System.out.println("PKCS7 padding hex: " + HexString.fromBytes(pad_bytes));
	}
	
	public static void question2_2() {
		System.out.println("Question 2.2 : Implement CBC mode");
		byte[] ciphertext_bytes = Base64.getDecoder().decode(CryptoExamples.getContent(Q2_2_FILENAME));
		try {
			System.out.println("----- Create AES Instance using key : " + Q2_2_PKCS7_STR + " -----");
			AES aes = new AES(Q2_2_PKCS7_STR);
			System.out.println("----- Create CBC associated to ASE Instance -----");
			CBC aes_128_cbc = new CBC(aes, ECB.BLOCKSIZE);
			System.out.println("----- Decrypt file : " + Q2_2_FILENAME + " -----");
			byte[] plaintext_bytes = aes_128_cbc.decrypt(ciphertext_bytes);
			System.out.println(new String(plaintext_bytes));
		} catch (Exception e) {
			e.getMessage();
		}
	}
	
	public static void question2_3() {
		System.out.println("Question 2.3 : An ECB/CBC detection oracle");
		String data = "";
		System.out.println("----- Create AES ORACLE instance----- ");
		AES_ORACLE aes_oracle 	= new AES_ORACLE();
		//pour avoir des blocks qui se repetent dans les donnees cryptees
		System.out.println("----- Use repeating string : AAA...----- ");
		for(int i=0; i<100; i++) {
			data += "A";
		}
		System.out.println("----- ASE Oracle encryption of previous data ----- ");
		byte[] 	 encrypted_bytes = aes_oracle.oracle_encrypt(data.getBytes());
		System.out.print("----- Guessing Mode : ");
		if(ECB.detect_ecb(encrypted_bytes)) {
			System.out.println("ECB Mode");
		}else {
			System.out.println("not ECB Mode => CBC ");
		}
	}
	
	public static void question2_4() {
		System.out.println("Question 2.4 : Byte-at-a-time ECB decryption (Simple)");
		AES_ORACLE aes_oracle 	= new AES_ORACLE();		
		String cipher_secret_string = "";
		try {
			System.out.println("----- Secret String Base64 to String -----");
			cipher_secret_string = new String(Base64.getDecoder().decode(Q2_4_APPEND_STR), "UTF-8");
		} catch (Exception e) {
			e.getMessage();
		}
		//trouver la taille du block ECB 
		//on repete le caractere A puis en encryptant a chanque fois
		//puis on regarde quand  est ce que le block precedant aparait dans la prochaine iteration
		//puis on sort avec la taille du bloc trouvée = l'iteration d'avant
		System.out.println("----- Detect AES Oracle block size -----");
		byte[] 	 encrypted_bytes_curr = "".getBytes();
		byte[]   encrypted_bytes_prev = "".getBytes();
		int prev_size = 1;
		int block_size;
		String data = "";
		for(block_size = 1; block_size < 24; block_size++) {
			data += "A";
			encrypted_bytes_curr = aes_oracle.oracle_ecb( (data).getBytes() );
			if(Arrays.equals(
					Arrays.copyOf(encrypted_bytes_curr, prev_size), encrypted_bytes_prev)
					) {
				block_size -= 1;
				break;
			}
			encrypted_bytes_prev= encrypted_bytes_curr;
			prev_size 			= encrypted_bytes_prev.length;
		}
		System.out.println("Block size found : " + block_size);
		System.out.println("encryp bytes prev    (block_size = 16): " + HexString.fromBytes(encrypted_bytes_prev));
		System.out.println("encryp bytes current (block_size = 17): " + HexString.fromBytes(encrypted_bytes_curr));
		
		//Detecter le mode ECB
		//faire en sorte d'avoir plusieurs blocks ECB
		//puis utiliser la fonction qui detect l'ECB
		System.out.println("----- Detect AES Oracle Mode -----");
		data = "";
		for(int i= 1; i < 64; i++) {
			data += "A";			
		}
		byte[] plaintext_bytes = (data + cipher_secret_string).getBytes();
		encrypted_bytes_curr = aes_oracle.oracle_ecb( plaintext_bytes );
		System.out.print("Guessing AES Oracle Mode :");
		if(ECB.detect_ecb(encrypted_bytes_curr)) {
			System.out.println(" ECB");
		}else {
			System.out.println(" not ECB");
		}
		
		//question final
		System.out.println("----- Decrypt Secret String -----");
		int    nb_block 			   = cipher_secret_string.length() / ECB.BLOCKSIZE + 1;
		String plaintext_secret_string = "";
		for(int blk = 0; blk < nb_block; blk++) {
			for(int byte_index = ECB.BLOCKSIZE-1; byte_index >= 0; byte_index--) {
				String As = "";
				for(int i = 0; i < byte_index; i++) {
					As += "A";
				}
				byte[] cipherAsWithSecret       = aes_oracle.oracle_ecb ( ( As + cipher_secret_string ).getBytes());
				byte[] cipherAsWithSecret_block = Arrays.copyOfRange( cipherAsWithSecret, blk*ECB.BLOCKSIZE, (blk+1)*ECB.BLOCKSIZE);
				for(char c = 0; c < 256; c++ ) {
					String str        = As + plaintext_secret_string + c + cipher_secret_string;
					byte[] cipher     = aes_oracle.oracle_ecb(str.getBytes());
					byte[] cipher_blk = Arrays.copyOfRange(cipher, blk*ECB.BLOCKSIZE, (blk+1)*ECB.BLOCKSIZE);
					if(Arrays.equals(cipherAsWithSecret_block, cipher_blk)) {	
						plaintext_secret_string += c;
						break;
					}
				}
			}
		}
		System.out.println(plaintext_secret_string);

	}

}
