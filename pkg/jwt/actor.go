package jwt

import (
	"errors"
	"fmt"
	"maps"
	"slices"
)

// Claim names registered by OAuth specifications that build on JWT.
const (
	Actor        Public = "act"       // https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1
	MayAct       Public = "may_act"   // https://www.rfc-editor.org/rfc/rfc8693.html#section-4.4
	Scope        Public = "scope"     // https://www.rfc-editor.org/rfc/rfc8693.html#section-4.2
	ClientID     Public = "client_id" // https://www.rfc-editor.org/rfc/rfc8693.html#section-4.3
	Confirmation Public = "cnf"       // https://www.rfc-editor.org/rfc/rfc7800.html#section-3.1
)

// MaxActors bounds how deep an "act" claim may nest.
const MaxActors = 32

// ErrActor means an "act" or "may_act" claim is malformed.
var ErrActor = errors.New("jwt: invalid actor claim")

// A Party identifies one party in a delegation chain: the value of an "act"
// claim without its nested "act", or of a "may_act" claim.
//
// https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1
type Party struct {
	// Subject is the party's "sub". It is required.
	Subject string
	// Issuer is the party's "iss", when the subject is only unique within
	// an issuer.
	Issuer string
	// Claims holds any other identity claims, such as "client_id". It never
	// holds "sub", "iss" or "act", nor "exp", "nbf" or "aud", which RFC 8693
	// §4.1 says are not meaningful for an actor.
	Claims map[string]any
}

// nonIdentity are the claims RFC 8693 §4.1 forbids inside "act".
var nonIdentity = []string{ExpirationTime, NotBefore, Audience}

// Actors returns the delegation chain an "act" claim records, the current
// actor first and each earlier actor after it. A token without "act" has
// no actors.
//
// When a token exchange service re-issues a token on behalf of a new
// actor, it records the new actor in front of the existing ones; see
// [ClaimsSet.SetActors].
//
// https://www.rfc-editor.org/rfc/rfc8693.html#section-4.1
func (claims ClaimsSet) Actors() ([]Party, error) {
	raw, ok := claims[Actor]
	if !ok {
		return nil, nil
	}
	var chain []Party
	for {
		if len(chain) == MaxActors {
			return nil, fmt.Errorf("%w: more than %d nested actors", ErrActor, MaxActors)
		}
		object, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: %q must be a JSON object", ErrActor, Actor)
		}
		party, err := partyFrom(object, true)
		if err != nil {
			return nil, err
		}
		chain = append(chain, party)
		if raw, ok = object[Actor]; !ok {
			return chain, nil
		}
	}
}

// SetActors records actors as nested "act" claims, the current actor first.
// An empty chain removes the claim.
//
// To re-issue a token for a new actor while keeping the lineage:
//
//	actors, err := subject.Actors()
//	...
//	err = claims.SetActors(append([]jwt.Party{newActor}, actors...))
func (claims ClaimsSet) SetActors(actors []Party) error {
	if len(actors) == 0 {
		delete(claims, Actor)
		return nil
	}
	if len(actors) > MaxActors {
		return fmt.Errorf("%w: more than %d nested actors", ErrActor, MaxActors)
	}
	var nested map[string]any
	for _, party := range slices.Backward(actors) {
		object, err := party.object()
		if err != nil {
			return err
		}
		if nested != nil {
			object[Actor] = nested
		}
		nested = object
	}
	claims[Actor] = nested
	return nil
}

// AllowedActor returns the party a "may_act" claim authorizes to act for
// the subject, and false if the token has no "may_act".
//
// https://www.rfc-editor.org/rfc/rfc8693.html#section-4.4
func (claims ClaimsSet) AllowedActor() (Party, bool, error) {
	raw, ok := claims[MayAct]
	if !ok {
		return Party{}, false, nil
	}
	object, ok := raw.(map[string]any)
	if !ok {
		return Party{}, false, fmt.Errorf("%w: %q must be a JSON object", ErrActor, MayAct)
	}
	party, err := partyFrom(object, false)
	if err != nil {
		return Party{}, false, err
	}
	return party, true, nil
}

// Is reports whether p and other name the same party: the same subject
// and issuer. Other identity claims are not compared.
func (p Party) Is(other Party) bool {
	return p.Subject == other.Subject && p.Issuer == other.Issuer
}

func partyFrom(object map[string]any, nestable bool) (Party, error) {
	var p Party
	for name, value := range object {
		switch name {
		case Subject, Issuer:
			s, ok := value.(string)
			if !ok || s == "" {
				return Party{}, fmt.Errorf("%w: %q must be a non-empty string", ErrActor, name)
			}
			if name == Subject {
				p.Subject = s
			} else {
				p.Issuer = s
			}
		case Actor:
			if !nestable {
				return Party{}, fmt.Errorf("%w: %q cannot nest %q", ErrActor, MayAct, Actor)
			}
		default:
			if slices.Contains(nonIdentity, name) {
				return Party{}, fmt.Errorf("%w: %q is not an identity claim", ErrActor, name)
			}
			if p.Claims == nil {
				p.Claims = map[string]any{}
			}
			p.Claims[name] = value
		}
	}
	if p.Subject == "" {
		return Party{}, fmt.Errorf("%w: missing %q", ErrActor, Subject)
	}
	return p, nil
}

func (p Party) object() (map[string]any, error) {
	if p.Subject == "" {
		return nil, fmt.Errorf("%w: missing %q", ErrActor, Subject)
	}
	object := maps.Clone(p.Claims)
	if object == nil {
		object = map[string]any{}
	}
	for _, name := range append([]string{Subject, Issuer, Actor}, nonIdentity...) {
		if _, ok := object[name]; ok {
			return nil, fmt.Errorf("%w: Claims cannot hold %q", ErrActor, name)
		}
	}
	object[Subject] = p.Subject
	if p.Issuer != "" {
		object[Issuer] = p.Issuer
	}
	return object, nil
}
