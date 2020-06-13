/*
 * Copyright (C) 2020 Matthew Rosato
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.t07m.encryption;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {
	
	public static SecretKeySpec createSecretKey(String password, String salt) {
		try {
			return createSecretKey(password.toCharArray(), salt.getBytes(), 40000, 128);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {}
		return null;
	}

	public static byte[] encrypt(SecretKeySpec key, byte[] data) {
		try {
			Random r = new Random();
			int line = 30;
			StringBuilder sb = new StringBuilder(new String(internalencrypt(data, key)));
			for(;;) {
				int val = 0;
				while(val == 0 && sb.length()-line > 3) {
					val = r.nextInt(Math.min(9, sb.length()-line));
				}
				sb.insert(line, val);
				if(val == 0)
					break;
				line += val;
			}
			return sb.toString().getBytes();
		} catch (UnsupportedEncodingException | GeneralSecurityException e) {}
		return null;
	}

	public static boolean isEncrypted(byte[] data) {
		if(data != null) {
			int line = 30;
			StringBuilder sb = new StringBuilder(new String(data));
			for(;;) {
				if(line >= sb.length())
					return false;
				try {
					int val = Integer.parseInt(String.valueOf(sb.charAt(line)));
					if(val > 9)
						return false;
					sb.deleteCharAt(line);
					line += val-1;
					if(val == 0)
						return true;
				}catch(NumberFormatException e) {
					return false;
				}
			}
		}else {
			return false;
		}
	}

	public static byte[] decrypt(SecretKeySpec key, byte[] data) {
		try {
			int line = 30;
			StringBuilder sb = new StringBuilder(new String(data));
			for(;;) {
				int val = Integer.parseInt(String.valueOf(sb.charAt(line)));
				sb.deleteCharAt(line);
				line += val-1;
				if(val == 0)
					break;
			}
			return new String(internaldecrypt(sb.toString(), key)).getBytes();
		} catch (GeneralSecurityException | IOException | NumberFormatException e) {}
		return null;
	}

	private static SecretKeySpec createSecretKey(char[] password, byte[] salt, int iterationCount, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
		SecretKey keyTmp = keyFactory.generateSecret(keySpec);
		return new SecretKeySpec(keyTmp.getEncoded(), "AES");
	}

	private static byte[] internalencrypt(byte[] data, SecretKeySpec key) throws GeneralSecurityException, UnsupportedEncodingException {
		Cipher pbeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		pbeCipher.init(Cipher.ENCRYPT_MODE, key);
		AlgorithmParameters parameters = pbeCipher.getParameters();
		IvParameterSpec ivParameterSpec = parameters.getParameterSpec(IvParameterSpec.class);
		byte[] cryptoText = pbeCipher.doFinal(data);
		byte[] iv = ivParameterSpec.getIV();
		return (base64Encode(iv) + ":" + base64Encode(cryptoText)).getBytes();
	}

	private static String base64Encode(byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}

	private static byte[] internaldecrypt(String string, SecretKeySpec key) throws GeneralSecurityException, IOException {
		byte[] iv = string.split(":")[0].getBytes();
		byte[] property = string.split(":")[1].getBytes();
		Cipher pbeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		pbeCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(base64Decode(iv)));
		return pbeCipher.doFinal(base64Decode(property));
	}

	private static byte[] base64Decode(byte[] property) throws IOException {
		return Base64.getDecoder().decode(property);
	}

}
