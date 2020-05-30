package crypto.examples;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

public class CryptoExamples {
	 public static InputStream getInputStream(String filename) {
		 	InputStream inputStream = null;
	        try {
	        	//prendre le fichier dans le meme package que cette classe comme stream
	        	inputStream = CryptoExamples.class.getResourceAsStream(filename);
	        } catch (Exception e) {
	            System.out.println(e.getMessage());
	        }
	        //retourné le stream
	        return inputStream;
	    }
	 public static String getContent(String filename) {
		 	try {
		 		//prendre le stream (voir fonction en haut) puis creer un bufferReader
		 		BufferedReader input = new BufferedReader(new InputStreamReader( getInputStream(filename),"UTF-8"));
		 		String line = null;
				String content = "";
				//lire ligne par ligne
				while ((line = input.readLine()) != null) {
					content += line;				
				}
				//fermé le fichier
				input.close();
				return content;	
		 	}catch (Exception e) {
				System.out.println(e.getMessage());
				return null;
			}
	 }
}
