#include "Firewall.h"

Firewall::Firewall(string ruleFileName)
{
	/**
	 * Parse File into rules vector
	 */
	std::ifstream ruleFile(ruleFileName);

	string line;
	while (std::getline(ruleFile, line))
	{
		std::replace(line.begin(), line.end(), ',', ' ');
		std::stringstream ss(line);
		string direction, protocol, ports, ips;
		ss >> direction >> protocol >> ports >> ips;

		/**
		 * Determine if the port and ip contain a single value or a range
		 */
		bool portIsRange = ports.find("-") != string::npos;
		bool ipIsRange = ips.find("-") != string::npos;
		std::replace(ports.begin(), ports.end(), '-', ' ');	
		std::replace(ips.begin(), ips.end(), '-', ' ');
		std::stringstream ssPorts(ports);
		std::stringstream ssIps(ips);

		/**
		 * Create the rule, and fill in the starting and ending ports/IPs
		 * If the port/IP is a range, then the ePort/eIp will come from sstream
		 * Otherwise, it will remain the same as the starting port/IP
		 * Add it to the vector of rules
		 */
		Rule rule;
		rule.type = serialize_booleans(direction, protocol);
		ssPorts >> rule.sPort >> rule.ePort;
		ssIps >> rule.sIp >> rule.eIp;
		rule.ePort = portIsRange ? rule.ePort : rule.sPort;
		rule.eIp = ipIsRange ? rule.eIp : rule.sIp;
		rules.push_back(rule);
	}

	/**
	 * Sort the rules by type (see serialize function), starting port, and starting IP
	 */
	std::sort(rules.begin(), rules.end(), [](const Rule& x, const Rule& y) {
		return (x.type == y.type) ? (x.sPort == y.sPort ? (x.sIp.compare(y.sIp) < 0) : x.sPort < y.sPort) : x.type < y.type;
	});
}

bool Firewall::accept_packet(string direction, string protocol, int port, string ip)
{
	char classification = serialize_booleans(direction, protocol);
	Rule rule;
	rule.type = serialize_booleans(direction, protocol);
	rule.sPort = port;
	rule.ePort = port;
	rule.sIp = ip;
	rule.eIp = ip;

	/**
	 * The usage of this lambda would have saved a few lines of code (specifically gotten rid of the binary_search function)
	 * However, the comparator needs to return a boolean and I my compare() function returns an int
	 * I believe the correct solution would be to overload the == operator, but I ran out of time
	 * So i just did the simple 'vanilla' binary search...
	 */
	// return std::binary_search(rules.begin(), rules.end(), rule, CANNOT FIND A FUNCTION);
	return binary_search(0, rules.size() - 1, rule);
}

bool Firewall::binary_search(int leftIndex, int rightIndex, const Rule& rule)
{
	/**
	 * No longer a valid search
	 */
	if (leftIndex > rightIndex)
	{
		return false;
	}

	/**
	 * Find the difference between the middle element and 'rule' using Rule::compare()
	 * If the index < rule, then the current middle index is too small, so search the right subarray
	 * If the index > rule, then the current middle index is too large, so search the left subarray
	 */
	int middleIndex = leftIndex + (rightIndex - leftIndex) / 2;
	int difference = rules[middleIndex].compare(rule);
	return (difference == 0) ? true : (difference < 0 ? binary_search(middleIndex + 1, rightIndex, rule) : binary_search(leftIndex, middleIndex - 1, rule));
}

char Firewall::serialize_booleans(string direction, string protocol)
{
	/**
	 * Serializes (outbound udp) (outbound tcp) (inbound udp) & (inbound tcp) to A B C & D respectively
	 */
	return (65 + 2 * ((direction == "inbound") ? true : false) + ((protocol == "tcp") ? true : false));
}



/**
 * Main test function below
 * Contains 25 labelled test cases, in their own subcategories
 * 
 * The fw.csv file attached includes the original 4 cases, + 8 more
 * These cases were just added mainly to test the sorting functionality
 */

/*
int main(int argc, char const *argv[])
{
	Firewall fw("fw.csv");

	// 5 stock cases given in the original document
	std::cout << std::boolalpha << fw.accept_packet("inbound", "tcp", 80, "192.168.1.2") << std::endl;			// true
	std::cout << std::boolalpha << fw.accept_packet("inbound", "udp", 53, "192.168.2.1") << std::endl;			// true
	std::cout << std::boolalpha << fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11") << std::endl;	// true
	std::cout << std::boolalpha << fw.accept_packet("inbound", "tcp", 81, "192.168.1.2") << std::endl;			// false
	std::cout << std::boolalpha << fw.accept_packet("inbound", "udp", 24, "52.12.48.92") << std::endl;			// false

	// test for individual port cases
	std::cout << std::boolalpha << fw.accept_packet("inbound", "tcp", 0, "0.0.0.0") << std::endl;				// false
	std::cout << std::boolalpha << fw.accept_packet("inbound", "tcp", 1, "0.0.0.0") << std::endl;				// true
	std::cout << std::boolalpha << fw.accept_packet("inbound", "tcp", 2, "0.0.0.0") << std::endl;				// true
	std::cout << std::boolalpha << fw.accept_packet("inbound", "tcp", 3, "0.0.0.0") << std::endl;				// true
	std::cout << std::boolalpha << fw.accept_packet("inbound", "tcp", 4, "0.0.0.0") << std::endl;				// true

	// test for individual IP cases
	std::cout << std::boolalpha << fw.accept_packet("inbound", "tcp", 5, "0.0.0.0") << std::endl;				// false
	std::cout << std::boolalpha << fw.accept_packet("inbound", "tcp", 5, "1.0.0.0") << std::endl;				// true
	std::cout << std::boolalpha << fw.accept_packet("inbound", "tcp", 5, "2.0.0.0") << std::endl;				// true
	std::cout << std::boolalpha << fw.accept_packet("inbound", "tcp", 5, "3.0.0.0") << std::endl;				// true
	std::cout << std::boolalpha << fw.accept_packet("inbound", "tcp", 5, "4.0.0.0") << std::endl;				// true

	// test for IP range cases on boundaries
	std::cout << std::boolalpha << fw.accept_packet("inbound", "udp", 53, "192.168.1.0") << std::endl;			// false
	std::cout << std::boolalpha << fw.accept_packet("inbound", "udp", 53, "192.168.1.1") << std::endl;			// true
	std::cout << std::boolalpha << fw.accept_packet("inbound", "udp", 53, "192.168.2.5") << std::endl;			// true
	std::cout << std::boolalpha << fw.accept_packet("inbound", "udp", 53, "192.168.2.6") << std::endl;			// false
	std::cout << std::boolalpha << fw.accept_packet("inbound", "udp", 52, "192.168.2.1") << std::endl;			// true

	// test for port rage cases on boundaries
	std::cout << std::boolalpha << fw.accept_packet("outbound", "udp", 999, "52.12.48.92") << std::endl;		// false
	std::cout << std::boolalpha << fw.accept_packet("outbound", "udp", 1000, "52.12.48.92") << std::endl;		// true
	std::cout << std::boolalpha << fw.accept_packet("outbound", "udp", 2000, "52.12.48.92") << std::endl;		// true
	std::cout << std::boolalpha << fw.accept_packet("outbound", "udp", 2001, "52.12.48.92") << std::endl;		// false
	std::cout << std::boolalpha << fw.accept_packet("outbound", "udp", 1000, "52.12.48.93") << std::endl;		// false

	return 0;
}
*/