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

import java.lang.reflect.ParameterizedType;

import javax.crypto.spec.SecretKeySpec;

import com.t07m.encryption.Encryption;

import net.cubespace.Yamler.Config.InternalConverter;
import net.cubespace.Yamler.Config.Converter.Converter;

public class EncryptedStringConverter implements Converter{

	public static SecretKeySpec KEY = Encryption.createSecretKey(System.getenv("COMPUTERNAME"), System.getenv("TMP"));;

	public EncryptedStringConverter(InternalConverter internalConverter) {
		
	}

	public Object toConfig(Class<?> type, Object obj, ParameterizedType parameterizedType) throws Exception {
		var encryptedString = (EncryptedString) obj;
		if(encryptedString != null )
			return encryptedString.getEncrypted();
		return null;
	}

	public Object fromConfig(Class<?> type, Object obj, ParameterizedType parameterizedType) throws Exception {
		if(obj instanceof String) {
			var encryptedString = new EncryptedString((String) obj);
			if(encryptedString != null )
				return encryptedString;
		}else if (obj instanceof EncryptedString) {
			var encryptedString = (EncryptedString) obj;
			if(encryptedString != null )
				return encryptedString;
		}
		return null;
	}

	public boolean supports(Class<?> type) {
		return EncryptedString.class.isAssignableFrom(type);
	}

}