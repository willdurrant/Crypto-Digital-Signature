package com.willdurrant.crypto.signature.rsa;
import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

import codec.x509.X509Certificate;
import de.flexiprovider.common.util.ByteUtils;
import de.flexiprovider.core.FlexiCoreProvider;

public class ExampleSMIMEVerifyRSA {

    public static void main(String[] args) throws Exception {

	Security.addProvider(new FlexiCoreProvider());
	
	ClassLoader classLoader = ExampleSMIMESignRSA.class.getClassLoader();

	File file = new File(classLoader.getResource("MyEmail").getFile());
	byte[] message = new byte[(int) file.length()];
	FileInputStream fis = new FileInputStream(file);
	fis.read(message);
	fis.close();

	file = new File("generated-signature/RSASignature.sig");
	byte[] sigBytes = new byte[(int) file.length()];
	fis = new FileInputStream(file);
	fis.read(sigBytes);
	fis.close();

	file = new File(classLoader.getResource("rsa/CertRSA.cer").getFile());
	byte[] encCertRSA = new byte[(int) file.length()];
	fis = new FileInputStream(file);
	fis.read(encCertRSA);
	fis.close();

	file = new File(classLoader.getResource("certificate-authority/UserCA.cer").getFile());
	byte[] encCertCA = new byte[(int) file.length()];
	fis = new FileInputStream(file);
	fis.read(encCertCA);
	fis.close();

	X509Certificate certRSA = new X509Certificate(encCertRSA);
	X509Certificate certCA = new X509Certificate(encCertCA);

	MessageDigest md = MessageDigest.getInstance("SHA1", "FlexiCore");

	md.update(encCertRSA);
	System.out.println("SHA1 fingerprint of \"CertRSA.cer\": "
		+ ByteUtils.toHexString(md.digest()));

	md.update(encCertCA);
	System.out.println("SHA1 fingerprint of \"UserCA.cer\" : "
		+ ByteUtils.toHexString(md.digest()));

	PublicKey pubKeyCA = certCA.getPublicKey();

	certRSA.checkValidity();
	certRSA.verify(pubKeyCA, "FlexiCore");
	System.out.println("The signature of \"CertRSA.cer\" verifies: true");

	certCA.checkValidity();
	certCA.verify(pubKeyCA, "FlexiCore");
	System.out.println("The signature of \"UserCA.cer\" verifies : true");

	System.out.println("=> The Certificate Chain is valid!\n");

	PublicKey pubKeyRSA = certRSA.getPublicKey();

	Signature sig = Signature.getInstance("SHA1withRSA", "FlexiCore");

	sig.initVerify(pubKeyRSA);
	sig.update(message);
	boolean isValid = sig.verify(sigBytes);

	System.out.println("The signature of the email verifies: " + isValid
		+ "\n");
    }

}