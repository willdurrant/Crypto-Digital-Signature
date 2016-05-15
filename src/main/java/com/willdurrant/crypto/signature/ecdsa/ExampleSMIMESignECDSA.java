package com.willdurrant.crypto.signature.ecdsa;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;

import codec.asn1.DERDecoder;
import codec.pkcs12.PFX;
import codec.pkcs12.PKCS8ShroudedKeyBag;
import codec.pkcs12.SafeBag;
import de.flexiprovider.core.FlexiCoreProvider;
import de.flexiprovider.ec.FlexiECProvider;

/**
 * TODO - Doesn't work due to IOException("Only named ECParameters supported") being caught
 * when using the password "certECDSA".
 * @author will
 *
 */
public class ExampleSMIMESignECDSA {

    public static void main(String[] args) throws Exception {

	Security.addProvider(new FlexiCoreProvider());
	Security.addProvider(new FlexiECProvider());

	ClassLoader classLoader = ExampleSMIMESignECDSA.class.getClassLoader();
	
	DERDecoder dec = new DERDecoder(classLoader.getResourceAsStream("ecdsa/CertECDSA.p12"));
	PFX pfx = new PFX();
	pfx.decode(dec);

	SafeBag safeBag = pfx.getAuthSafe().getSafeContents(0).getSafeBag(0);
	PKCS8ShroudedKeyBag kBag = (PKCS8ShroudedKeyBag) safeBag.getBagValue();

	char[] password = "certECDSA".toCharArray();
	PrivateKey privKey = kBag.getPrivateKey(password);

	File file = new File(classLoader.getResource("MyEmail").getFile());
	byte[] buffer = new byte[(int) file.length()];
	FileInputStream fis = new FileInputStream(file);
	fis.read(buffer);
	fis.close();

	Signature sig = Signature.getInstance("SHA1withECDSA", "FlexiEC");

	sig.initSign(privKey);
	sig.update(buffer);
	byte[] sigBytes = sig.sign();

	FileOutputStream fos = new FileOutputStream("generated-signature/ECDSASignature.sig");
	fos.write(sigBytes);
	fos.close();
    }

}