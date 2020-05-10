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
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.org.apache.xml.internal.security.algorithms.MessageDigestAlgorithm;

public class ClientLogic {
	private PrivateKey clientPrivateKey = null;
	private PublicKey clientPublicKey = null;
	
	public String getPublicKey() {
		if(clientPublicKey == null) {
			return null;
		}
		return Base64.getEncoder().encodeToString(clientPublicKey.getEncoded());
	}
	
	public String getPublicKeyFormat() {
		return clientPublicKey == null ? "Key Not setted" : clientPublicKey.getFormat();
	}
	
	public String getPrivateKey() {
		if(clientPrivateKey == null) {
			return null;
		}
		return Base64.getEncoder().encodeToString(clientPrivateKey.getEncoded());
	}
	
	public String getPrivateKeyFormat() {
		return clientPrivateKey == null ? "Key Not setted" : clientPrivateKey.getFormat();
	}
	
	public String keyGenerate() throws NoSuchAlgorithmException {
		SecureRandom secureRandom = new SecureRandom();
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(1024,secureRandom);
		
		KeyPair keyPair = generator.genKeyPair();
		
		clientPrivateKey = keyPair.getPrivate();
		clientPublicKey = keyPair.getPublic();
		
		return Base64.getEncoder().encodeToString(clientPrivateKey.getEncoded());
	}
	
	public Map<String, Object> MakeEnvelop(String serverPublicKey, byte[] aesKey, byte[] data ) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, JsonProcessingException, UnsupportedEncodingException, InvalidKeySpecException {
		if(clientPrivateKey == null || clientPublicKey == null) {
			System.out.println("Key Not Generated");
			return null;
		}
		//Plain Document
		String plainDocument = new String(data);
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		byte[] hashedPlainDocumentByte = messageDigest.digest(data);
		
		Cipher rsaCipher = Cipher.getInstance("RSA");
		rsaCipher.init(Cipher.ENCRYPT_MODE, clientPrivateKey);
		byte[] encryptedHashedPlainDocumentByte = rsaCipher.doFinal(hashedPlainDocumentByte);
		//Encrypted Plain Document Hash
		String encryptedHashedPlainDocumentStr = Base64.getEncoder().encodeToString(encryptedHashedPlainDocumentByte);
		//Client Public Key
		String publicKeyStr = Base64.getEncoder().encodeToString(clientPublicKey.getEncoded());
		
		Map<String, Object> electronicEnvelop = new HashMap<String, Object>();
		electronicEnvelop.put("PlainDocument", plainDocument);
		electronicEnvelop.put("HashedDocument", encryptedHashedPlainDocumentStr);
		electronicEnvelop.put("ClientPublicKey", publicKeyStr);
		
		ObjectMapper envelopMapper = new ObjectMapper();
		String plainMappdEnvelopStr = envelopMapper.writeValueAsString(electronicEnvelop);
		
		//AesKey
		Cipher envelopCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		aesKey = sha1.digest(aesKey);
		aesKey = Arrays.copyOf(aesKey, 16);
		SecretKeySpec keySpec = new SecretKeySpec(aesKey,"AES");
		
		//Encrypt Envelop
		envelopCipher.init(Cipher.ENCRYPT_MODE, keySpec);
		byte[] encryptedEnvelop = envelopCipher.doFinal(plainMappdEnvelopStr.getBytes("UTF-8"));
		String encryptedEnvelopStr = Base64.getEncoder().encodeToString(encryptedEnvelop);

		//Restore Server Public Key
		byte[] publicKeyByte = Base64.getDecoder().decode(serverPublicKey);
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyByte);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey restoredServerPublicKey = keyFactory.generatePublic(publicKeySpec);
		
		// Encrypt AES Key
		Cipher aesKeyCipher = Cipher.getInstance("RSA");
		aesKeyCipher.init(Cipher.ENCRYPT_MODE, restoredServerPublicKey);
		byte[] encryptAesKey = aesKeyCipher.doFinal(keySpec.getEncoded());
		String encryptAesKeyStr = Base64.getEncoder().encodeToString(encryptAesKey);
		
		
		Map<String,Object> retval = new HashMap<String, Object>();
		retval.put("key", encryptAesKeyStr);
		retval.put("envelop", encryptedEnvelopStr);
		
		return retval;
	}
}
