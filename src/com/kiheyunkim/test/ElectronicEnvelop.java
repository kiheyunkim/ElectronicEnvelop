package com.kiheyunkim.test;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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
			System.out.println("private Format :" + serverPrivateKey.getFormat());
			System.out.println("private :" + new String(serverPrivateKey.getEncoded()));
			System.out.println("private Format :" + serverPublicKey.getFormat());
			System.out.println("public :" + new String(serverPublicKey.getEncoded().toString()));
			
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
			System.out.println("public :" + new String(publicKey2.getEncoded().toString()));
			
			
			//공개키를 받은 Client의 시작
			System.out.println("Client Start");
			//서버의 공개키를 받았다고 가정.
			String baseEncodedPublicKey = encodedStringPublicKey;
			generator.initialize(1024, secureRandom);
			
			KeyPair clientkeyPair = generator.genKeyPair();
			
			//클라이언트의 키생성
			System.out.println("Create Client Key");
			clientPrivateKey = clientkeyPair.getPrivate();
			clientPublicKey = clientkeyPair.getPublic();
			System.out.println("private Format :" + clientPrivateKey.getFormat());
			System.out.println("private :" + new String(clientPrivateKey.getEncoded()));
			System.out.println("private Format :" + clientPublicKey.getFormat());
			System.out.println("public :" + new String(clientPublicKey.getEncoded().toString()));
			
			
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}

	
	static public void main(String[] args) {
		Server();
	}
}
