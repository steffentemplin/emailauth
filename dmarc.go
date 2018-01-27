package emailauth

/*
 * Authentication-Results:
 *  mx.example.com;
 *  dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
 */

type DMARCResult struct {
	Result    Result
	Domain    string
	Alignment []string
	Tags      map[string]string // DMARC Tag Registry: adkim, aspf, ...
}

type DMARCValidator struct {
}

func (v DMARCValidator) Validate(message *Message, spfResult *SPFResult, dkimResult *DKIMResult) *DMARCResult {
	return newDMARCResult(None)
}

func newDMARCResult(result Result) *DMARCResult {
	r := &DMARCResult{Result: result}
	r.Alignment = make([]string, 2)
	r.Tags = make(map[string]string)
	return r
}
