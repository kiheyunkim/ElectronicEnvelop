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
			
			serverPublicKey = keyPair.getPublic();
			serverPrivateKey = keyPair.getPrivate();
						
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		
			X509EncodedKeySpec rsaPublicKeySpec = keyFactory.getKeySpec(serverPublicKey, X509EncodedKeySpec.class);
			PKCS8EncodedKeySpec rsaPrivateKeySpec = keyFactory.getKeySpec(serverPrivateKey, PKCS8EncodedKeySpec.class);
			/*
			System.out.println("Server Public  key modulus : " + rsaPublicKeySpec.getModulus());
			System.out.println("Server Public  key exponent: " + rsaPublicKeySpec.getPublicExponent());
			System.out.println("Server Private key modulus : " + rsaPrivateKeySpec.getModulus());
			System.out.println("Server Private key exponent: " + rsaPrivateKeySpec.getPrivateExponent());
			*/
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}
	
	static void Client() {
		SecureRandom secureRandom = new SecureRandom();
		System.out.println("------Client Start------");
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(1024, secureRandom);
			
			KeyPair keyPair = generator.genKeyPair();
			
			clientPublicKey = keyPair.getPublic();
			clientPrivateKey = keyPair.getPrivate();
						
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		
			X509EncodedKeySpec rsaPublicKeySpec = keyFactory.getKeySpec(serverPublicKey, X509EncodedKeySpec.class);
			PKCS8EncodedKeySpec rsaPrivateKeySpec = keyFactory.getKeySpec(serverPrivateKey, PKCS8EncodedKeySpec.class);
			
			String plainText = "Hello World!";
			
			try {
				Cipher ciper = Cipher.getInstance("RSA");
				ciper.init(Cipher.ENCRYPT_MODE, clientPublicKey);
				
				byte[] encrypt = ciper.doFinal(plainText.getBytes());
				System.out.println("Plain:" + new String(plainText));
				System.out.println("Encrypt:" + new String(encrypt));
				
				ciper.init(Cipher.DECRYPT_MODE, clientPrivateKey);
				
			} catch (InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			/*
			 * System.out.println("Client Public  key modulus : " +
			 * rsaPublicKeySpec.getModulus());
			 * System.out.println("Client Public  key exponent: " +
			 * rsaPublicKeySpec.getPublicExponent());
			 * System.out.println("Client Private key modulus : " +
			 * rsaPrivateKeySpec.getModulus());
			 * System.out.println("Client Private key exponent: " +
			 * rsaPrivateKeySpec.getPrivateExponent());
			 */ 
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}
	
	static public void main(String[] args) {
		Server();
		Client();
	}
}
