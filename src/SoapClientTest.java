import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import de.dfncert.soap.DFNCERTPublic;
import de.dfncert.soap.DFNCERTTypesValidDomain;
import de.dfncert.tools.*;

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
		DFNCERTTypesValidDomain[] validDomains = publicClient.getValidDomains(options.raId, "server"); // server or email or "" for all
		
		System.out.println("Showing "+ validDomains.length + " valid server domains: ");
		for(DFNCERTTypesValidDomain d : validDomains)
			System.out.println("- " + d.getName());
		
		
		System.out.println("Done.");
	}
	
	public static class CommandLineOptions {
		@Option(name="-ra-id",usage="RA Id")
		int raId;
		
		@Option(name="-p12file")
	    String p12File;
	    
		@Option(name="-password")
	    String password;
	    
		@Option(name="-caname")
	    String caName = "test-client1-ca";
		
		@Override
		public String toString() {
			return "CommandLineOptions [raId=" + raId + ", p12File=" + p12File + ", password=" + password + ", caName="
					+ caName + "]";
		}
		
	}
	
	private static CommandLineOptions parse(String[] args) throws CmdLineException {
		CommandLineOptions options = new CommandLineOptions();
		CmdLineParser parser = new CmdLineParser(options);
		parser.parseArgument(args);
		return options;
	} 
	

}
