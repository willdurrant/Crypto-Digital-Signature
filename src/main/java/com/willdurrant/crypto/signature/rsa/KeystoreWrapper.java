package com.willdurrant.crypto.signature.rsa;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.Enumeration;

/**
 * Generated keystore with following command;
 *  keytool -importcert -file UserCA.cer -keystore keystore.jks -alias "Alias"
 * @author will
 *
 */
public class KeystoreWrapper {

	public static void main(String[] args) throws Exception{

		ClassLoader classLoader = KeystoreWrapper.class.getClassLoader();
		
		try {

	        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
	        String password = "123456";
	        keystore.load(classLoader.getResourceAsStream("certificate-authority/keystore.jks"), password.toCharArray());


	        Enumeration enumeration = keystore.aliases();
	        while(enumeration.hasMoreElements()) {
	            String alias = (String)enumeration.nextElement();
	            System.out.println("alias name: " + alias);
	            Certificate certificate = keystore.getCertificate(alias);
	            System.out.println(certificate.toString());

	        }

	    } catch (java.security.cert.CertificateException e) {
	        e.printStackTrace();
	    } catch (NoSuchAlgorithmException e) {
	        e.printStackTrace();
	    } catch (FileNotFoundException e) {
	        e.printStackTrace();
	    } catch (KeyStoreException e) {
	        e.printStackTrace();
	    } catch (IOException e) {
	        e.printStackTrace();
	    }finally {
	       
	    }
		    
		    
	}
	
}
