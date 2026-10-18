package vanmoof

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// What Invitations does with the account's bike sharing invitations
const (
	InvitationsList    = "list"
	InvitationsAccept  = "accept"
	InvitationsDecline = "decline"
)

// Model returns the model of the bike the invitation is for, as Bike.Model does
func (i Invitation) Model() string {
	return Bike{BleProfile: i.BleProfile}.Model()
}

// Invitations lists the account's pending bike sharing invitations, or accepts or declines
// the ones in selection: "all", or their numbers in the list or GUIDs, comma-separated.
// Without a selection, it lists them and asks which.
func Invitations(email, action, selection string, opts Options) error {
	debug := opts.Debug
	s, _, err := login(email, debug, opts.NoCache)
	if err != nil {
		return err
	}
	defer cacheRenewedTokens(email, s.Tokens(), s, debug, opts.NoCache)

	invitations, err := s.Invitations()
	if err != nil {
		return fmt.Errorf("failed to get the bike sharing invitations: %w", err)
	}
	if len(invitations) == 0 {
		fmt.Println("No pending bike sharing invitations")
		return nil
	}
	if action == InvitationsList || selection == "" {
		printInvitations(invitations)
	}
	if action == InvitationsList {
		return nil
	}

	selected, err := selectInvitations(invitations, action, selection)
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		fmt.Println("No invitations selected")
		return nil
	}

	// Go on with the others when one fails, but report it
	failed := 0
	for _, inv := range selected {
		if err := respondToInvitation(s, inv, action); err != nil {
			fmt.Printf("Failed to %s the invitation for %s: %v\n", action, Redact(inv.BikeName), ScrubText(err.Error()))
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d invitation(s) failed", failed, len(selected))
	}
	return nil
}

// printInvitations prints the invitations, numbered as selectInvitations takes them
func printInvitations(invitations []Invitation) {
	for i, inv := range invitations {
		fmt.Printf("Invitation %d\n", i+1)
		fmt.Printf("Bike: %s\n", Redact(inv.BikeName))
		fmt.Printf("Model: %s\n", printable(cmp.Or(inv.Model(), inv.ModelName)))
		fmt.Printf("Owner: %s\n", Redact(inv.OwnerName))
		if inv.ExpiresAt != "" {
			fmt.Printf("Expires: %s\n", printable(inv.ExpiresAt))
		}
		if inv.EndsAt != "" {
			fmt.Printf("Shared until: %s\n", printable(inv.EndsAt))
		}
		fmt.Printf("GUID: %s\n", Redact(inv.GUID))
		fmt.Println()
	}
}

// selectInvitations returns the invitations in selection: "all", or their numbers in the
// list or GUIDs, comma-separated. Without a selection, it asks which to accept or decline.
// An invitation given twice is selected once.
func selectInvitations(invitations []Invitation, action, selection string) ([]Invitation, error) {
	if selection == "" {
		fmt.Printf("Invitations to %s (numbers or GUIDs, comma-separated, or 'all'; nothing for none): ", action)
		input, err := ReadLine()
		if err != nil {
			return nil, fmt.Errorf("failed to read input: %w", err)
		}
		selection = input
	}
	if selection == "all" {
		return invitations, nil
	}

	var selected []Invitation
	seen := make(map[int]bool)
	for part := range strings.SplitSeq(selection, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		i := slices.IndexFunc(invitations, func(inv Invitation) bool { return strings.EqualFold(inv.GUID, part) })
		if n, err := strconv.Atoi(part); err == nil && n >= 1 && n <= len(invitations) {
			i = n - 1
		}
		if i < 0 {
			return nil, fmt.Errorf("no pending invitation %s", Redact(part))
		}
		if !seen[i] {
			seen[i] = true
			selected = append(selected, invitations[i])
		}
	}
	return selected, nil
}

// respondToInvitation accepts or declines the invitation, and says so
func respondToInvitation(s *Session, inv Invitation, action string) error {
	if action == InvitationsDecline {
		if err := s.DeclineInvitation(inv.GUID); err != nil {
			return err
		}
		fmt.Printf("Declined the invitation for %s from %s\n", Redact(inv.BikeName), Redact(inv.OwnerName))
		return nil
	}

	bike, err := s.AcceptInvitation(inv.GUID)
	if err != nil {
		return err
	}
	shared := Redact(cmp.Or(bike.Name, inv.BikeName))
	if bike.FrameNumber != "" {
		shared += " (frame number " + RedactID(bike.FrameNumber) + ")"
	}
	fmt.Printf("Accepted the invitation for %s from %s\n", shared, Redact(cmp.Or(bike.Owner, inv.OwnerName)))
	return nil
}
