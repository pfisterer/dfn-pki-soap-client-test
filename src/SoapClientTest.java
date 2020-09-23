import java.io.Reader;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import de.dfncert.soap.DFNCERTPublic;
import de.dfncert.soap.DFNCERTTypesValidDomain;
import de.dfncert.tools.Cryptography;
import de.dfncert.tools.DFNPKIClient;

public class SoapClientTest {

	public static void main(String[] args) throws Exception {
		// Parse command line options
		CommandLineOptions options = parse(args);
		System.out.println("Options = " + options);

		// Create client
		DFNPKIClient client = new DFNPKIClient(options.caName);
		client.loadRAFromPKCS12(options.p12File, options.password.toCharArray());
		DFNCERTPublic publicClient = client.getPublic();

		// Get CA name
		System.out.println("CA Name: " + client.getCAName());

		// List valid domains
		DFNCERTTypesValidDomain[] validDomains = publicClient.getValidDomains(options.raId, "server"); // server or
																										// email or ""
		System.out.println("Showing " + validDomains.length + " valid server domains: ");
		for (DFNCERTTypesValidDomain d : validDomains)
			System.out.println("- " + d.getName());

		// Create request
		String csr = Files.readString(Paths.get(options.csrFile));

		Reader pemReader = new StringReader(csr);
		PEMParser pemParser = new PEMParser(pemReader);
		PKCS10CertificationRequest certificationRequest = (PKCS10CertificationRequest) pemParser.readObject();
		X500Name subject = certificationRequest.getSubject();

		for (String san : extractSanFromCsr(certificationRequest)) {
			System.out.println("SAN:"+ san);
		}
		
		
		/*
		 * int newRequestId = newRequest(publicClient, options.raId, csr,
		 * options.altNames, options.role, Cryptography.sha1(options.pin.getBytes()),
		 * options.addName, options.addEMail, options.AddOrgUnit, options.publish);
		 * 
		 * // Antragsdaten holen, diese signieren und damit Antrag genehmigen byte raw[]
		 * = client.getRegistration().getRawRequest(newRequestId);
		 * client.getRegistration().approveRequest(newRequestId, raw,
		 * Cryptography.createPKCS7Signed(raw, client.getRAPrivateKey(),
		 * client.getRACertificate()));
		 */

		System.out.println("Done.");
	}

	

	/**
	 *
	 * @publicClient Soap client instance
	 * 
	 *               Copied from the documentation:
	 * 
	 * @param RaID       xsd:int Nummer der RA, 0 für die Master-RA
	 * @param PKCS10     xsd:string Der Zertifikatantrag im PEM-Format
	 * @param AltNames   xsd:string[] Subject Alternative Names in der Form
	 *                   ("typ:wert", ...)
	 * @param Role       xsd:string Die Rolle des beantragten Zertifikats
	 * @param Pin        xsd:string Sperrkennwort für das Zertifikat als SHA-1 Hash
	 * @param AddName    xsd:string Vollständiger Name des Antragstellers
	 * @param AddEMail   xsd:string E-Mail Adresse des Antragstellers
	 * @param AddOrgUnit xsd:string Abteilung des Antragstellers
	 * @param Publish    xsd:boolean Veröffentlichung des Zertifikats
	 * 
	 * @return xsd:int Die Seriennummer des hochgeladenen Antrags
	 * @throws Exception
	 */
	public static int newRequest(DFNCERTPublic publicClient, int RaID, String PKCS10, String[] AltNames, String Role,
			String Pin, String AddName, String AddEMail, String AddOrgUnit, boolean Publish) throws Exception {

		return publicClient.newRequest(RaID, PKCS10, AltNames, Role, Pin, AddName, AddEMail, AddOrgUnit, Publish);
	}

	private static List<String> extractSanFromCsr(PKCS10CertificationRequest csr) {
		List<String> sans = new ArrayList<>();
		Attribute[] certAttributes = csr.getAttributes();
		
		for (Attribute attribute : certAttributes) {
			
			if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
				Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
				GeneralNames gns = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
				GeneralName[] names = gns.getNames();
			
				for (GeneralName name : names) {
					String title = "";
					if (name.getTagNo() == GeneralName.dNSName) {
						title = "DNS";
					} else if (name.getTagNo() == GeneralName.iPAddress) {
						title = "IP Address";
					} else if (name.getTagNo() == GeneralName.otherName) {
						title = "Other Name";
					}
					
					sans.add(title + ": " + name.getName());
				}
			}
		}

		return sans;
	}
	public static class CommandLineOptions {
		@Option(name = "-ra-id", usage = "RA Id")
		int raId;

		@Option(name = "-p12file")
		String p12File;

		@Option(name = "-password")
		String password;

		@Option(name = "-caname")
		String caName = "test-client1-ca";

		@Option(name = "-csrfile")
		String csrFile = "csr/myserver.csr";

		@Option(name = "-altnames", usage = "Subject Alternative Names in der Form \"typ:wert\", ...)")
		String[] altNames = {};

		@Option(name = "-role", usage = "Die Rolle des beantragten Zertifikats")
		String role = "Web Server";

		@Option(name = "-pin")
		String pin = "123456";

		@Option(name = "-addName", usage = "Vollständiger Name des Antragstellers")
		String addName = "";

		@Option(name = "-addEMail", usage = "E-Mail Adresse des Antragstellers")
		String addEMail = "bla@example.com";

		@Option(name = "-AddOrgUnit", usage = "Abteilung des Antragstellers")
		String AddOrgUnit = "Foo Inc.";

		@Option(name = "-publish", usage = "Veröffentlichung des Zertifikats")
		boolean publish = true;

		@Override
		public String toString() {
			return "CommandLineOptions [raId=" + raId + ", p12File=" + p12File + ", password=" + password + ", caName="
					+ caName + ", csrFile=" + csrFile + "]";
		}

	}

	private static CommandLineOptions parse(String[] args) throws CmdLineException {
		CommandLineOptions options = new CommandLineOptions();
		CmdLineParser parser = new CmdLineParser(options);
		parser.parseArgument(args);
		return options;
	}

	public static void demoCodeFromDocs() throws Exception {
		// RSA-Schlüsselpaar erzeugen
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		KeyPair pair = generator.generateKeyPair();

		// PKCS#10-Antrag erzeugen
		String request = Cryptography.createPKCS10("C=DE,O=Testinstallation Eins CA,OU=PCA,CN=Max Mustermann",
				pair.getPublic(), pair.getPrivate());

		// CLient erzeugen und Antrag hochladen
		DFNPKIClient client = new DFNPKIClient("test-eins-ca");
		int serial = client.getPublic().newRequest(1, request, new String[] { "email:mustermann@example.org" }, "User",
				Cryptography.sha1("Sperr-PIN".getBytes()), "Max Mustermann", "mustermann@example.org", null, true);

		// Sperrprüfung einschalten
		client.setCheckRevocation(true);

		// RA-Zertifikat laden
		client.loadRAFromPKCS12("test-eins-ra1.p12", "test-eins".toCharArray());

		// Antragsdaten holen, diese signieren und damit Antrag genehmigen
		byte raw[] = client.getRegistration().getRawRequest(serial);
		client.getRegistration().approveRequest(serial, raw,
				Cryptography.createPKCS7Signed(raw, client.getRAPrivateKey(), client.getRACertificate()));

		// Alle 10 Sekunden nach ausgestelltem Zertifikat fragen
		String pem = "";
		while (pem.equals("")) {
			Thread.sleep(10000l);
			pem = client.getRegistration().getCertificateByRequestSerial(serial);
		}

	}

}
