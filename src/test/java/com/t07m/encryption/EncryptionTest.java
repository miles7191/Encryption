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

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

class EncryptionTest {

	@Test
	void EncryptDecrypt() {
		var data = "Super Secret";
		SecretKeySpec key = Encryption.createSecretKey("Password", "Salt");
		byte[] encrypted = Encryption.encrypt(key, data.getBytes());
		byte[] decrypted = Encryption.decrypt(key, encrypted);
		assert(data.contentEquals(new String(decrypted)));
	}

	
	@Test
	void IsEncrypted() {
		var data = "Super Secret";
		SecretKeySpec key = Encryption.createSecretKey("Password", "Salt");
		byte[] encrypted = Encryption.encrypt(key, data.getBytes());
		assert(Encryption.isEncrypted(encrypted));
	}
}
