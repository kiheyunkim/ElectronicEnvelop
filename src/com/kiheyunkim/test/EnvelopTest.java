package com.kiheyunkim.test;


import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.core.JsonProcessingException;

public class EnvelopTest {
	@Test
	public void Test() {
		ServerLogic server = new ServerLogic();
		String key = null;
		try {
			key = server.keyGenerate();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		System.out.println("ServerPublic Key :" + key);
		
		ClientLogic client = new ClientLogic();
		try {
			client.keyGenerate();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		String aesKey = "이건 AES 키";
		String data = "이건 평문입니다.";
		
		
		Map<String, Object> envelopResult = null;
		try {
			envelopResult = client.MakeEnvelop(key, aesKey.getBytes(), data.getBytes());
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | JsonProcessingException | UnsupportedEncodingException
				| InvalidKeySpecException e) {
			e.printStackTrace();
		}

		String resultKey = (String) envelopResult.get("key");
		String resultEnvelop = (String) envelopResult.get("envelop");
		System.out.println("Encrypted Key: " + resultKey);
		System.out.println("Encrypted envelop: " + resultEnvelop);
		
		String plain = null;
		try {
			plain = server.getPlainDocument(resultKey, resultEnvelop);			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		System.out.println(plain);
		
		assertEquals(data, plain);
		
	}
}
