package agility

import "fmt"

// preference order: PostQuantum > Hybrid > Classical
var typeScore = map[AlgorithmType]int{
	PostQuantum: 3,
	Hybrid:      2,
	Classical:   1,
}

// Negotiate picks the strongest mutually-supported algorithm from two
// advertised lists, preferring post-quantum > hybrid > classical.
// Returns an error if no common algorithm is found.
func Negotiate(local, remote []string, reg *Registry) (*Algorithm, error) {
	remoteSet := make(map[string]bool, len(remote))
	for _, id := range remote {
		remoteSet[id] = true
	}

	var best *Algorithm
	for _, id := range local {
		if !remoteSet[id] {
			continue
		}
		a, err := reg.Get(id)
		if err != nil {
			continue
		}
		if a.Status == Deprecated {
			continue
		}
		if best == nil || typeScore[a.Type] > typeScore[best.Type] {
			best = a
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no common algorithm between local %v and remote %v", local, remote)
	}
	return best, nil
}

// NegotiationResult records the outcome of an algorithm negotiation.
type NegotiationResult struct {
	Selected       *Algorithm
	LocalOffered   []string
	RemoteOffered  []string
	Reason         string
}

// NegotiateWithReason wraps Negotiate and returns a richer result for display.
func NegotiateWithReason(local, remote []string, reg *Registry) NegotiationResult {
	a, err := Negotiate(local, remote, reg)
	if err != nil {
		return NegotiationResult{
			LocalOffered:  local,
			RemoteOffered: remote,
			Reason:        "no common algorithm — handshake fails",
		}
	}
	reason := fmt.Sprintf("both peers support %q; selected as strongest shared algorithm (%s)", a.ID, a.Type)
	return NegotiationResult{
		Selected:      a,
		LocalOffered:  local,
		RemoteOffered: remote,
		Reason:        reason,
	}
}
