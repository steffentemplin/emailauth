package emailauth

import (
	"net"
	"regexp"
	"strings"
)

/*
 * Authentication-Results:
 *  mx1.example.com;
 *  spf=pass (mailfrom)
 *   smtp.mailfrom=example.com (client-ip=192.168.5.24; helo=example.com; envelope-from=test@example.com; receiver=<UNKNOWN>)
 *
 * Authentication-Results:
 *  mx1.example.com;
 *  spf=pass smtp.mailfrom=hans-test@example.com
 *
 * Received-SPF:
 *  Pass (mailfrom) identity=mailfrom;
 *  client-ip=192.168.5.24;
 *  helo=example.com;
 *  envelope-from=test@example.com;
 *  receiver=recipient@acme.org
 */

type SPFResult struct {
	Result      Result
	Explanation string
}

type SPFValidator struct {
}

func newSPFResult(result Result, explanation string) *SPFResult {
	r := &SPFResult{Result: result, Explanation: explanation}
	return r
}

const recordPrefix = "v=spf1"

var directiveExp = regexp.MustCompile("^(?P<qualifier>\\+|-|\\?|~)?(?P<mech>all|include|a|mx|ptr|ip4|ip6|exists)(?:(?P<sep>[:/])(?P<value>.*))?$")
var modifierExp = regexp.MustCompile("^(?P<name>[a-z][a-z0-9_\\-\\.]*)=(?P<macrostring>.*)$")
var domainExp = regexp.MustCompile("^([^\\.]+\\.)+[^\\.]+(\\.)?$")

func (v SPFValidator) Validate(ip net.IP, from string, heloName string) *SPFResult {
	heloName = strings.TrimSpace(heloName)
	if isValidDomain(heloName) {
		// TODO: check HELO SPF
	}

	from = strings.TrimSpace(from)
	if len(from) == 0 {
		from = "@" + heloName
	}

	if from[0] == '<' {
		from = from[1:]
	}

	if from[len(from)-1] == '>' {
		from = from[0 : len(from)-1]
	}

	fromParts := strings.Split(from, "@")
	if len(fromParts) != 2 {
		// FIXME: right result?
		return newSPFResult(Permerror, "Invalid sender address")
	}

	localPart := strings.TrimSpace(fromParts[0])
	if len(localPart) == 0 {
		localPart = "postmaster"
	}

	domain := strings.TrimSpace(fromParts[1])
	if isInvalidDomain(domain) {
		return newSPFResult(None, "Invalid domain name")
	}

	record, errResult := findSPFRecord(domain)
	if errResult != nil {
		return errResult
	}

	return handlePolicyRecord(record, ip)
}

func findSPFRecord(domain string) (string, *SPFResult) {
	records, err := net.LookupTXT(domain)
	if err != nil {
		if err, ok := err.(*net.DNSError); ok {
			if err.IsTimeout || err.IsTemporary {
				return "", newSPFResult(Temperror, err.Error())
			}
		}
		// FIXME: right result?
		return "", newSPFResult(None, err.Error())
	}

	var record string
	for _, r := range records {
		if strings.HasPrefix(r, recordPrefix) {
			if len(r) > len(recordPrefix)+1 && r[len(recordPrefix)] == ' ' {
				if record != "" {
					return "", newSPFResult(Permerror, "Multiple SPF records")
				}

				record = r
			} else if r == recordPrefix {
				// FIXME: right result?
				return "", newSPFResult(Neutral, "No policies specified")
			}
		}
	}

	if record == "" {
		return "", newSPFResult(None, "")
	}

	return record, nil
}

func handlePolicyRecord(record string, ip net.IP) *SPFResult {
	return checkRecursive(ip, record, 0)
}

func checkRecursive(ip net.IP, record string, depth int8) *SPFResult {
	record = record[len(recordPrefix)+1 : len(record)]
	terms := strings.Split(record, " ")
	for _, t := range terms {
		//"^(+-?)?$"
		if t[0] == '+' {

		}
	}

	return newSPFResult(None, "")
}

func isValidDomain(domain string) bool {
	regexMatch := domainExp.MatchString(domain)
	if regexMatch {
		// must not be an IPv4 address
		return net.ParseIP(domain) == nil
	}

	return false
}

func isInvalidDomain(domain string) bool {
	return !isValidDomain(domain)
}
