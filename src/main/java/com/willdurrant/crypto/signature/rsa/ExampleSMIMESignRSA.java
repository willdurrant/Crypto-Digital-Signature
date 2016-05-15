package com.willdurrant.crypto.signature.rsa;
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

public class ExampleSMIMESignRSA {

    public static void main(String[] args) throws Exception {

	Security.addProvider(new FlexiCoreProvider());

	ClassLoader classLoader = ExampleSMIMESignRSA.class.getClassLoader();
	
	DERDecoder dec = new DERDecoder(classLoader.getResourceAsStream("rsa/CertRSA.p12"));
	PFX pfx = new PFX();
	pfx.decode(dec);

	SafeBag safeBag = pfx.getAuthSafe().getSafeContents(0).getSafeBag(0);
	PKCS8ShroudedKeyBag kBag = (PKCS8ShroudedKeyBag) safeBag.getBagValue();

	char[] password = "certRSA".toCharArray();
	PrivateKey privKey = kBag.getPrivateKey(password);

	File file = new File(classLoader.getResource("MyEmail").getFile());
	byte[] buffer = new byte[(int) file.length()];
	FileInputStream fis = new FileInputStream(file);
	fis.read(buffer);
	fis.close();

	Signature sig = Signature.getInstance("SHA1withRSA", "FlexiCore");

	sig.initSign(privKey);
	sig.update(buffer);
	byte[] sigBytes = sig.sign();

	FileOutputStream fos = new FileOutputStream("generated-signature/RSASignature.sig");
	fos.write(sigBytes);
	fos.close();
    }

}