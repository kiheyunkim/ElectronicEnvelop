package com.kiheyunkim.test;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ServerLogic {
	private PrivateKey serverPrivateKey = null;
	private PublicKey serverPublicKey = null;
	
	public String getPublicKey() {
		if(serverPublicKey == null) {
			return null;
		}
		return Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
	}
	
	public String getPublicKeyFormat() {
		return serverPublicKey == null ? "Key Not setted" : serverPublicKey.getFormat();
	}
	
	public String getPrivateKey() {
		if(serverPrivateKey == null) {
			return null;
		}
		return Base64.getEncoder().encodeToString(serverPrivateKey.getEncoded());
	}
	
	public String getPrivateKeyFormat() {
		return serverPrivateKey == null ? "Key Not setted" : serverPrivateKey.getFormat();
	}
	
	public String keyGenerate() throws NoSuchAlgorithmException {
		SecureRandom secureRandom = new SecureRandom();
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024,secureRandom);
		
		KeyPair keyPair = generator.genKeyPair();
		
		serverPrivateKey = keyPair.getPrivate();
		serverPublicKey = keyPair.getPublic();
		
		return Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
	}
	
	public String getPlainDocument(String keyPart, String documentPart) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, 
			BadPaddingException, UnsupportedEncodingException, JsonMappingException, JsonProcessingException, InvalidKeySpecException {
		byte[] encryptAesKey = Base64.getDecoder().decode(keyPart);
		byte[] envelop = Base64.getDecoder().decode(documentPart);
		
		Cipher rsaCipher = Cipher.getInstance("RSA");
		rsaCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
		byte[] decryptAesKey = rsaCipher.doFinal(encryptAesKey);
		
		SecretKeySpec aesSecretKeySpec = new SecretKeySpec(decryptAesKey,"AES"); 
		Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		aesCipher.init(Cipher.DECRYPT_MODE, aesSecretKeySpec);
		byte[] decryptEnvelopByte = aesCipher.doFinal(envelop);
		String decryptEnvelopByteStr = new String(decryptEnvelopByte,"UTF-8");
		
		ObjectMapper envelopMap = new ObjectMapper();
		HashMap<String, Object> decryptedEnvelopMap = envelopMap.readValue(decryptEnvelopByteStr, HashMap.class);
		String plainDocument = (String) decryptedEnvelopMap.get("PlainDocument");
		String EncryptedHash =  (String) decryptedEnvelopMap.get("HashedDocument");
		String clientPublicKey = (String) decryptedEnvelopMap.get("ClientPublicKey");
		
		//client publicKey restored
		X509EncodedKeySpec restoredRsaPublicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(clientPublicKey));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey restoredClientPublicKey = keyFactory.generatePublic(restoredRsaPublicKeySpec);
		
		Cipher rsaCipher2 = Cipher.getInstance("RSA");
		rsaCipher2.init(Cipher.DECRYPT_MODE, restoredClientPublicKey);
		byte[] decryptedHash = rsaCipher2.doFinal(Base64.getDecoder().decode(EncryptedHash));
		
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		byte[] hashedPlainDocument = messageDigest.digest(plainDocument.getBytes("UTF-8"));
		
		if(!Arrays.equals(decryptedHash,hashedPlainDocument)) {
			System.out.println("Integrity Fail");
			return "Integrity Fail";
		}
		
		
		
		return plainDocument;
	}
	
}






















