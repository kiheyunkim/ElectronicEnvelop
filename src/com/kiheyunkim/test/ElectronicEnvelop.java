package com.kiheyunkim.test;

import java.io.IOException;
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
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


public class ElectronicEnvelop {

	static private PublicKey serverPublicKey = null;
	static private PrivateKey serverPrivateKey = null;
	static private PublicKey clientPublicKey = null;
	static private PrivateKey clientPrivateKey = null;
	
	static void Server() {
		SecureRandom secureRandom = new SecureRandom();
		System.out.println("------Server Start------");
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(1024, secureRandom);
			
			KeyPair keyPair = generator.genKeyPair();
			
			//키생성
			System.out.println("Server key Created");
			serverPublicKey = keyPair.getPublic();
			serverPrivateKey = keyPair.getPrivate();
			System.out.println("Server private Format :" + serverPrivateKey.getFormat());
			System.out.println("Server private :" + new String(serverPrivateKey.getEncoded()));
			System.out.println("Server private Format :" + serverPublicKey.getFormat());
			System.out.println("Server public :" + new String(serverPublicKey.getEncoded()));
			
			//바이너리의 Base64 인코딩 (바이너리를 확인하기 위함 또는 전송용  -- Private에 대한 밑의 Server로직은 테스트를 위함. 다른 의미는 없음 public만 해야함)
			System.out.println("Convert Server Key for Printing");
			String encodedStringPrivateKey = Base64.getEncoder().encodeToString(serverPrivateKey.getEncoded());
			String encodedStringPublicKey = Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
			System.out.println("Byte To Base 64 private :" + encodedStringPrivateKey);
			System.out.println("Byte To Base 64 public :" + encodedStringPublicKey);
		
			//Base 64암호화 해제
			System.out.println("Decode Base 64 For Server");
			byte[] decodedPrivateKey = Base64.getDecoder().decode(encodedStringPrivateKey);
			byte[] decodedPublicKey = Base64.getDecoder().decode(encodedStringPublicKey);		
			System.out.println("private decoded:" + decodedPrivateKey);
			System.out.println("public decoded:" + decodedPublicKey);
			
			//byte[] 에서  Key Spec으로 변환
			System.out.println("Convert Byte To Key");
			PKCS8EncodedKeySpec rsaPrivateKeySpec = new PKCS8EncodedKeySpec(decodedPrivateKey);
			X509EncodedKeySpec rsaPublicKeySpec = new X509EncodedKeySpec(decodedPublicKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey2 = keyFactory.generatePrivate(rsaPrivateKeySpec);
			PublicKey publicKey2 = keyFactory.generatePublic(rsaPublicKeySpec);
			
			//다시 되돌리고 확인 - 실제 전송에서는 공개키만 보내야함.
			System.out.println("Decode Base 64 For Server");
			System.out.println("private Format :" + privateKey2.getFormat());
			System.out.println("private :" + new String(privateKey2.getEncoded()));
			System.out.println("private Format :" + publicKey2.getFormat());
			System.out.println("public :" + new String(publicKey2.getEncoded()));
			
			
			//공개키를 받은 Client의 시작
			System.out.println("Client Start");
			//서버의 공개키를 받았다고 가정.
			String serverSidePublicKeyStr = encodedStringPublicKey;
			generator.initialize(1024, secureRandom);
			
			KeyPair clientkeyPair = generator.genKeyPair();
			
			//클라이언트의 키생성
			System.out.println("Create Client Key");
			clientPrivateKey = clientkeyPair.getPrivate();
			clientPublicKey = clientkeyPair.getPublic();
			System.out.println("Client private Format :" + clientPrivateKey.getFormat());
			System.out.println("Client private :" + new String(clientPrivateKey.getEncoded()));
			System.out.println("Client private Format :" + clientPublicKey.getFormat());
			System.out.println("Client public :" + new String(clientPublicKey.getEncoded()));
			
			//원문 생성
			System.out.println("Create Document");
			String document = "Test Document This is for Bums";
			System.out.println("Plain Text: " + document);
			
			//문서 해시생성
			System.out.println("Create Document Hashing");
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
			byte[] documentHash = messageDigest.digest(document.getBytes());
			System.out.println("Document Hash :"+Base64.getEncoder().encodeToString(documentHash));
			
			//문서 Client 개인키로 암호화
			System.out.println("Encrypt Docuemnt hasing With Client Public key");
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, clientPrivateKey);
			byte[] encryptedDocumentHash = cipher.doFinal(documentHash);
			System.out.println("Encrypted Document Hash :"+Base64.getEncoder().encodeToString(encryptedDocumentHash));

			//전자봉투 생성
			System.out.println("Create Electronic Envelop With Document Original +  Encrypted DocumentHash + Client PublicKey");
			Map<String, Object> electronicEnvelop = new HashMap<String, Object>();
			electronicEnvelop.put("PlainDocument", document);
			electronicEnvelop.put("EncryptDocument",encryptedDocumentHash);
			electronicEnvelop.put("ClientPublicKey", clientPublicKey.getEncoded());
			ObjectMapper electronicEnvelopMapper = new ObjectMapper();
			String mappedElectronicEnvelop = electronicEnvelopMapper.writeValueAsString(electronicEnvelop);
			System.out.println("Electronic Encelop Convert To String : "+ mappedElectronicEnvelop);
			
			
			//Make AES key
			System.out.println("Make AES Key");
			cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");			
			byte[] aesKey = "NeedMoreSecurityString".getBytes();
			MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
			aesKey =  sha1.digest(aesKey);
			aesKey = Arrays.copyOf(aesKey, 16);
			SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
			System.out.println("AES Key :"+Base64.getEncoder().encodeToString(keySpec.getEncoded()));
			
			//Encrypt Electronic Envelop
			System.out.println("Encrypt Electronic Envelop With AES");
			System.out.println("Plain Envelop: " + mappedElectronicEnvelop);
			byte[] encryptEnvelop = cipher.doFinal(mappedElectronicEnvelop.getBytes());
			System.out.println("Encrypt Envelop: " + Base64.getEncoder().encodeToString(encryptEnvelop));
			
			//Encrypt AES Key With RSA
			System.out.println("Encrypt AES Key With RSA");
			byte[] prevEncryptKey = keySpec.getEncoded();
			System.out.println("Plain AES KEY: " + Base64.getEncoder().encodeToString(prevEncryptKey));
			System.out.println("serverSidePublicKeyStr : " + serverSidePublicKeyStr);
			
			//서버에서 온 공개키 복원
			byte[] prevServerPublicRestored = Base64.getDecoder().decode(serverSidePublicKeyStr);
			System.out.println("serverSidePublicKeyStr To Byte[] : " +prevServerPublicRestored);
			X509EncodedKeySpec serverSidePublicKeySpec = new X509EncodedKeySpec(prevServerPublicRestored);
			
			PublicKey restoredServerPublicKey = keyFactory.generatePublic(serverSidePublicKeySpec);
			System.out.println("serverSidePublicKeyStr restored : " + new String(restoredServerPublicKey.getEncoded()));
			
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, restoredServerPublicKey);
			byte[] postEncryptAESKey = cipher.doFinal(prevEncryptKey);
			System.out.println("Encrypt AES KEY: " + Base64.getEncoder().encodeToString(postEncryptAESKey));
			
			String key = Base64.getEncoder().encodeToString(postEncryptAESKey);
			String envelop = Base64.getEncoder().encodeToString(encryptEnvelop);
			
			System.out.println("KeyPart:" +key);
			System.out.println("EnvelopPart:" + envelop);
			
			
			System.out.println("Server Start - Decrypt Mode");
			PrivateKey decryptServerPrivateKey = serverPrivateKey;
			System.out.println("Server private :" + new String(decryptServerPrivateKey.getEncoded()));
			
			
			System.out.println("Key Decrypt With Server Private key");
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, decryptServerPrivateKey);
			byte[] decryptedAESKey = cipher.doFinal(Base64.getDecoder().decode(key));
			//AES키 해체
			System.out.println("Decrypted AES Key: " +Base64.getEncoder().encodeToString(decryptedAESKey));
			
			
			//봉투 해제
			System.out.println("open Electronic Envelop");
			cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			SecretKeySpec aesKeySpec = new SecretKeySpec(decryptedAESKey, "AES");
			cipher.init(Cipher.DECRYPT_MODE, keySpec);
			byte[] decryptedEvelop = cipher.doFinal(Base64.getDecoder().decode(envelop));
			String decryptedEnvelop = new String(decryptedEvelop);
			System.out.println("Decrpyted Envelop: " + decryptedEvelop);
			
			ObjectMapper envelopMapper = new ObjectMapper();
			HashMap<String, Object> decryptedEnvelopMap = envelopMapper.readValue(decryptedEvelop, HashMap.class);
			System.out.println("Envelop Open");
			System.out.println("PlainDocument: "+ decryptedEnvelopMap.get("PlainDocument"));
			System.out.println("EncryptDocument: "+ decryptedEnvelopMap.get("EncryptDocument"));
			System.out.println("ClientPublicKey: "+ decryptedEnvelopMap.get("ClientPublicKey"));
			/*
			 * electronicEnvelop.put("PlainDocument", document);
			 * electronicEnvelop.put("EncryptDocument",encryptedDocumentHash);
			 * electronicEnvelop.put("ClientPublicKey", clientPublicKey.getEncoded());
			 */
			
			
			
			
			
			
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	
	static public void main(String[] args) {
		Server();
	}
}
