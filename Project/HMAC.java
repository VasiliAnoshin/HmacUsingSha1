package HMAC;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;


public class HMAC {

	public static byte[] PerformEncription(byte[] data , byte[] key )
	{
		byte[] message;
		byte[] MAC;
		int macLenngth;
		byte[] i_key_pad ;
		byte[] o_key_pad;
		byte[] generatedHashedMessage;
		int blockSize = 64;
		byte[] tempKey = new byte[blockSize];
		int lengthOfTempMessage;		
		Sha1 sha1 = new Sha1();
						
		if (key.length > blockSize) {
			key = sha1.digestInBytes(key);
		}
		
		if(key.length < blockSize)
		{
			 System.arraycopy(key, 0, tempKey, 0, key.length);
		}
		
		o_key_pad = tempKey.clone();
		o_key_pad = GetOKey(o_key_pad , tempKey.length);		
		i_key_pad = tempKey.clone();
		i_key_pad = GetIKey(i_key_pad, tempKey.length);							

		lengthOfTempMessage = data.length + i_key_pad.length;
		
	    message = new byte[lengthOfTempMessage];		
		message = CreateMsg(message, i_key_pad , data);
		
		generatedHashedMessage = sha1.digestInBytes(message);
		
		macLenngth = o_key_pad.length + generatedHashedMessage.length;
		
		MAC = new byte[macLenngth];
		MAC = CreatePaddedMac(MAC, i_key_pad , o_key_pad , generatedHashedMessage );
		
		return sha1.digestInBytes(MAC);	
		
	}
	public static byte[] CreateMsg(byte[] message, byte[] i_key_pad, byte[] data)
	{
		System.arraycopy(i_key_pad, 0, message, 0, i_key_pad.length);
		System.arraycopy(data, 0, message, i_key_pad.length, data.length);
		return message;		
	}
	
	public static byte[] CreatePaddedMac(byte[] MAC, byte[] i_key_pad ,  byte[] o_key_pad , byte[] generatedHashedMessage ){
		System.arraycopy(o_key_pad, 0, MAC, 0, o_key_pad.length);
		System.arraycopy(generatedHashedMessage, 0, MAC, o_key_pad.length, generatedHashedMessage.length);
		return MAC;
	}
	
	public static byte[] GetOKey(byte[] oKey , int lengthOfTempKey)
	{
		for (int i = 0 ; i < lengthOfTempKey ; ++i) {
			oKey[i] ^= 0x5c;
			}
		return oKey;
	}
	public static byte[] GetIKey(byte[] iKey ,int lengthOfTempKey)
	{
		for (int i = 0 ; i < lengthOfTempKey ; ++i) {
			iKey[i] ^= 0x36;
			}
		return iKey;
	}

    public static void main(String[] args) throws IOException {
        byte[] messageInBytes = null;
        byte[] KeyPathinBytes = null;
        byte[] diggestFileInBytes= null; 
        Scanner reader = new Scanner(System.in);
        //Here we suppose to put input files 
        String messagePath = args[0];
        String keyPath = args[1];
        String digestFilePath =args[2];
        
        System.out.println("Please choose one of the following options : \n1) compute the digest and save it to the output file\n2)HMAC verification: compute the digest,"
        		+ " compare to the given digest file, and output either ACCEPT or REJECT depending on whether the two digests are equal \n");
        System.out.println("Press 1 or 2 ");
        int userChoose = reader.nextInt(); 
        
        if (userChoose == 1){
	        messageInBytes = readFile(messagePath);
	        KeyPathinBytes =  readFile(keyPath);       
	        
	        KeyPathinBytes = Base64.getDecoder().decode(KeyPathinBytes);        
	        String digest = null;
	        digest =  Base64.getEncoder().encodeToString(HMAC.PerformEncription(messageInBytes , KeyPathinBytes));
	        //System.out.println(digest);
	        createOutputFile(digest , digestFilePath);
        }else if(userChoose == 2){        	        
	        messageInBytes = readFile(messagePath);
	        KeyPathinBytes =  readFile(keyPath);
	        diggestFileInBytes =  readFile(digestFilePath);
	          
	        KeyPathinBytes = Base64.getDecoder().decode(KeyPathinBytes); 
	        diggestFileInBytes = Base64.getDecoder().decode(diggestFileInBytes);
	        byte[] generatedDigest = HMAC.PerformEncription(messageInBytes, KeyPathinBytes);
			
			if (Arrays.equals(generatedDigest, diggestFileInBytes)) {
				System.out.println("ACCEPT");
			} else {
				System.out.println("REJECT");
			}
        }
    }
    
    public static void createOutputFile(String digest , String path)
    {
    	try {
			File file = new File(path);
			// if file doesnt exists, then create it
			if (!file.exists()) {
				file.createNewFile();
			}
			FileWriter fw = new FileWriter(file.getAbsoluteFile());
			BufferedWriter bw = new BufferedWriter(fw);
			bw.write(digest);
			bw.close();

			System.out.println("Operation is DONE !!! ");

		} catch (IOException e) {
			e.printStackTrace();
		}
	}	
      
    public static void readFiles(String messagePath, String keyPath , String digestFile ,
    		byte[] diggestFileInBytes , byte[] messageInBytes ,byte[] KeyPathinBytes )
    {
    	    try {
				 messageInBytes = readFile(messagePath);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	        try {
				 KeyPathinBytes =  readFile(keyPath);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	        try {
				diggestFileInBytes =  readFile(digestFile);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    	
    }
    static private byte[] readFile(String path) throws IOException {    	       		    	 
    	     File file = new File(path);
             //Test if the file is empty or not.
             if (file.length() == 0){
                 System.out.println("There is nothing to read from the file :( ");
             }
             Path pathToFile = Paths.get(path);
             byte[] data = Files.readAllBytes(pathToFile);
            	                  
    	return data;
    }
}
