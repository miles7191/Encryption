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
package com.t07m.encryption.yamler;

import com.t07m.encryption.Encryption;

public class EncryptedString {

	private String encrypted, decrypted;
	private Object lock = new Object();

	public EncryptedString(String val) {
		setValue(val);
	}

	public void setValue(String val) {
		synchronized(lock) {
			if(val != null && Encryption.isEncrypted(val.getBytes())) {
				encrypted = val;
				decrypted = null;
			}else {
				decrypted = val;
				encrypted = null;
			}
		}
	}

	public String getEncrypted() {
		synchronized(lock) {
			if(encrypted == null && decrypted != null)
				encrypted = new String(Encryption.encrypt(EncryptedStringConverter.KEY, decrypted.getBytes()));
		}
		return encrypted;
	}

	public String getDecrypted() {
		synchronized(lock) {
			if(decrypted == null && encrypted != null)
				decrypted = new String (Encryption.decrypt(EncryptedStringConverter.KEY, encrypted.getBytes()));
		}
		return decrypted;
	}	
}