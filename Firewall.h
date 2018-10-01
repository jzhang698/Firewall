#pragma once
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <vector>

#define string std::string

struct Rule {
	char type;			// type determined by direction and protocol (see Firewall::serialize_boolean)
	int sPort, ePort;	// start and end of port range
	string sIp, eIp;	// start and end of IP range

	/**
	 * Performs the same functionality as the string compare function.
	 * lhs.compare(rhs) essentially returns the difference (lhs - rhs)
	 * We want to find if rhs falls in the range of lhs
	 * If it does, then compare returns 0, if not, then (lhs - rhs)
	 */
	int compare(const Rule& rhs)
	{
		if (type == rhs.type) {
			if (sPort <= rhs.sPort && ePort >= rhs.ePort)
			{

				/**
				 * At this point, the type and port matches. Now we determine whether the IP matches or not
				 * If the rhs IP falls between the current rule's start and end IPs, then it's a match and 0 is returned
				 * Otherwise, it returns the difference between the IPs. this difference is determined as follows:
				 *
				 * If the rhs IP is below the start of the range, then return the difference between the start and rhs.sIP
				 * However, if the rhs IP is above, it can either be in the range or above the range.
				 * Recall that the first part of the return already makes sure that it returns 0 if it's in the range
				 * Therefore, it must be above, so return the difference between the end of range and rhs IP (eIP - rhs.eIP)
				 */
				return (sIp.compare(rhs.sIp) <= 0 && eIp.compare(rhs.eIp) >= 0) ? 0 : (sIp.compare(rhs.sIp) < 0 ? eIp.compare(rhs.eIp) : sIp.compare(rhs.sIp));

			} 
			else
			{
				/**
				 * At this point, the type matches, but the port does not fall in the right range
				 *
				 * If the rhs Port is below the start of the port range, return (sPort - rhs.sPort)
				 * However, if the rhs port > sPort, then it must either fall in the range or be above
				 * Since we know that at this point, there is a port mismatch (not in range), rhs Port is above
				 * In this case, we will return the difference between the end of range and rhs port (ePort - rhs.ePort)
				 */
				return sPort - rhs.sPort < 0 ? ePort - rhs.ePort : sPort - rhs.sPort;
			}
		} 
		else {
			/**
			 * The rhs rule does not match this rule's direction or protocol
			 */
			return type - rhs.type;
		}
	}
};

class Firewall {

public:
	/**
	 * Firewall Constructor takes in filename
	 */
	Firewall(string ruleFileName);

	/**
	 * accept_packet takes in 4 packet header parameters and
	 * determines whether the packet will be accepted by the firewall
	 * TRUE = accepted, and FALSE = not accepted
	 */
	bool accept_packet(string direction, string protocol, int port, string ip);

private:

	/**
	 * Binary Search for rules in log(n) time (n corresponds to size of ruleFile)
	 */
	bool binary_search(int leftIndex, int rightIndex, const Rule& rule);

	/**
	 * Makes comparisons faster by a constant rate
	 * Slightly larger overhead for marginally faster runtime for rule matching
	 * Allows us to compare single characters instead of strings
	 * (Also could be used for a hashing implementation, so that there're fewer characters to hash)
	 */
	char serialize_booleans(string direction, string protocol);

	std::vector<Rule> rules;
};