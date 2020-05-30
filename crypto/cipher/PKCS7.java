package crypto.cipher;

public class PKCS7 {
	
	public static byte[] padding(byte[] input) {
		return padding(input, ECB.BLOCKSIZE);
	}
	public static byte[] padding(byte[] input, int block_size) {
		if(input.length % block_size == 0) {
			return input;
		}
		//Si la taille n'est pas un multiple de block faire le padding
		//+1 car on utilise la division entiere
		int nb_blocks = (input.length / block_size) + 1;
		//allocation tableau de byte pour le resultat : la taille = nb_block * block_size
		byte[] result = new byte[nb_blocks * block_size];
		//l'octet du padding est egale à : taille(result) - taille(input)
		byte pad = (byte) (result.length - input.length);
		//remplir le résultat : copier input dans result puis remplir avec pad le reste
		for(int i=0; i< result.length; i++) {
			if(i < input.length)
				result[i] = input[i];
			else
				result[i] = pad;
		}
		return result;
	}
}
