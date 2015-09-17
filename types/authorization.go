package types

import (
	"time"
)

type AuthorizationResource struct {
	Resource      ResourceAuthorizationTag `json:"resource"`
	DNSIdentifier DNSIdentifier            `json:"identifier,omitempty"`
	Status        AuthorizationStatus      `json:"status,omitempty"`
	Challenges    []Challenge              `json:"challenges,omitempty"`
	Combinations  [][]int                  `json:"combinations,omitempty"`
	Expires       *time.Time               `json:"expires,omitempty"`
}

type Authorization struct {
	Resource AuthorizationResource
	Location string
	// map challenge uri to per challenge data
	ChallengesData map[string]ChallengeData
}
