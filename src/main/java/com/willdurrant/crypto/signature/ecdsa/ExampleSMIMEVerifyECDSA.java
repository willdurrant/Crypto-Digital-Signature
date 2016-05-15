package com.willdurrant.crypto.signature.ecdsa;
import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

import codec.x509.X509Certificate;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.core.FlexiCoreProvider;
import de.flexiprovider.ec.FlexiECProvider;

public class ExampleSMIMEVerifyECDSA {

    public static void main(String[] args) throws Exception {

	Security.addProvider(new FlexiCoreProvider());
	Security.addProvider(new FlexiECProvider());

	ClassLoader classLoader = ExampleSMIMEVerifyECDSA.class.getClassLoader();
	
	File file = new File(classLoader.getResource("MyEmail").getFile());
	byte[] message = new byte[(int) file.length()];
	FileInputStream fis = new FileInputStream(file);
	fis.read(message);
	fis.close();

	file = new File("generated-signatures/ECDSASignature.sig");
	byte[] sigBytes = new byte[(int) file.length()];
	fis = new FileInputStream(file);
	fis.read(sigBytes);
	fis.close();

	file = new File(classLoader.getResource("ecdsa/CertECDSA.cer").getFile());
	byte[] encCertECDSA = new byte[(int) file.length()];
	fis = new FileInputStream(file);
	fis.read(encCertECDSA);
	fis.close();

	file = new File(classLoader.getResource("certificate-authority/UserCA.cer").getFile());
	byte[] encCertCA = new byte[(int) file.length()];
	fis = new FileInputStream(file);
	fis.read(encCertCA);
	fis.close();

	X509Certificate certECDSA = new X509Certificate(encCertECDSA);
	X509Certificate certCA = new X509Certificate(encCertCA);

	MessageDigest md = MessageDigest.getInstance("SHA1", "FlexiCore");

	md.update(encCertECDSA);
	System.out.println("SHA1 fingerprint of \"CertECDSA.cer\": "
		+ ByteUtils.toHexString(md.digest()));

	md.update(encCertCA);
	System.out.println("SHA1 fingerprint of \"UserCA.cer\"   : "
		+ ByteUtils.toHexString(md.digest()));

	PublicKey pubKeyCA = certCA.getPublicKey();

	certECDSA.checkValidity();
	certECDSA.verify(pubKeyCA, "FlexiCore");
	System.out.println("The signature of \"CertECDSA.cer\" verifies: true");

	certCA.checkValidity();
	certCA.verify(pubKeyCA, "FlexiCore");
	System.out.println("The signature of \"UserCA.cer\" verifies   : true");

	System.out.println("=> The certificate chain is valid!\n");

	PublicKey pubKeyECDSA = certECDSA.getPublicKey();

	Signature sig = Signature.getInstance("SHA1withECDSA", "FlexiEC");

	sig.initVerify(pubKeyECDSA);
	sig.update(message);
	boolean isValid = sig.verify(sigBytes);
	System.out.println("The signature of the email verifies: " + isValid);
    }

}