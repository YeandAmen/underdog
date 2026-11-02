package identity

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/YeandAmen/underdog/internal/domain"
)

var SupportedRights = map[string]bool{
	"local-admin": true, "reset-password": true, "write-members": true,
	"replicate-directory": true, "remote-logon": true, "read": true, "write": true,
}

func Validate(s domain.Snapshot) error {
	if s.PolicyVersion == "" || s.Organization == "" || s.CapturedAt.IsZero() {
		return fmt.Errorf("organization, policy_version, and captured_at are required")
	}
	principals, assets, groupIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, u := range s.Users {
		if u.ID == "" || u.Name == "" || u.Role == "" || principals[u.ID] {
			return fmt.Errorf("users require unique IDs, names, and roles")
		}
		principals[u.ID] = true
	}
	for _, g := range s.Groups {
		if g.ID == "" || g.Name == "" || principals[g.ID] {
			return fmt.Errorf("groups require unique IDs and names")
		}
		principals[g.ID] = true
		groupIDs[g.ID] = true
	}
	for _, g := range s.Groups {
		for _, member := range g.Members {
			if !principals[member] {
				return fmt.Errorf("group %s references unknown principal %s", g.ID, member)
			}
		}
	}
	for _, u := range s.Users {
		for _, group := range u.Groups {
			if !groupIDs[group] {
				return fmt.Errorf("user %s references unknown group %s", u.ID, group)
			}
		}
	}
	for _, a := range s.Assets {
		if a.ID == "" || assets[a.ID] {
			return fmt.Errorf("assets require unique IDs")
		}
		assets[a.ID] = true
	}
	grantIDs := map[string]bool{}
	for _, g := range s.Grants {
		if g.ID == "" || grantIDs[g.ID] || !principals[g.Principal] || !assets[g.Resource] || !SupportedRights[g.Right] || (g.Effect != "allow" && g.Effect != "deny") || g.InheritedDepth < 0 {
			return fmt.Errorf("grant %q has invalid principal, resource, right, effect, or inheritance", g.ID)
		}
		grantIDs[g.ID] = true
	}
	for _, p := range s.Policies {
		if p.Role == "" || !assets[p.Resource] {
			return fmt.Errorf("policy requires a role and a known resource")
		}
		for _, right := range p.Rights {
			if !SupportedRights[right] {
				return fmt.Errorf("unsupported policy right %q", right)
			}
		}
	}
	return nil
}

// MembershipPaths expands nested memberships breadth-first, preserving the
// shortest explanation path and terminating even when groups contain cycles.
func MembershipPaths(s domain.Snapshot, user domain.User) map[string][]string {
	paths := map[string][]string{user.ID: {user.Name}}
	parents, names := map[string][]string{}, map[string]string{}
	for _, group := range s.Groups {
		names[group.ID] = group.Name
		for _, member := range group.Members {
			parents[member] = append(parents[member], group.ID)
		}
	}
	parents[user.ID] = append(parents[user.ID], user.Groups...)
	queue := []string{user.ID}
	for len(queue) > 0 {
		principal := queue[0]
		queue = queue[1:]
		sort.Strings(parents[principal])
		for _, parent := range parents[principal] {
			if _, seen := paths[parent]; seen {
				continue
			}
			paths[parent] = append(append([]string{}, paths[principal]...), names[parent])
			queue = append(queue, parent)
		}
	}
	return paths
}

func Allowed(s domain.Snapshot, role, resource, right string) bool {
	for _, policy := range s.Policies {
		if strings.EqualFold(policy.Role, role) && policy.Resource == resource {
			for _, r := range policy.Rights {
				if r == right {
					return true
				}
			}
		}
	}
	return false
}

func Audit(s domain.Snapshot) []domain.Finding {
	assets := map[string]domain.Asset{}
	for _, asset := range s.Assets {
		assets[asset.ID] = asset
	}
	out := []domain.Finding{}
	for _, user := range s.Users {
		if !user.Enabled {
			continue
		}
		paths := MembershipPaths(s, user)
		grants := append([]domain.Grant{}, s.Grants...)
		sort.SliceStable(grants, func(i, j int) bool {
			a, b := grants[i], grants[j]
			if a.Inherited != b.Inherited {
				return !a.Inherited
			}
			if a.Inherited && a.InheritedDepth != b.InheritedDepth {
				return a.InheritedDepth < b.InheritedDepth
			}
			if a.Effect != b.Effect {
				return a.Effect == "deny"
			}
			return a.ID < b.ID
		})
		decided := map[string]bool{}
		for _, grant := range grants {
			path, hasPrincipal := paths[grant.Principal]
			key := grant.Resource + "\x00" + grant.Right
			if !hasPrincipal || decided[key] {
				continue
			}
			decided[key] = true
			if grant.Effect != "allow" || Allowed(s, user.Role, grant.Resource, grant.Right) {
				continue
			}
			severity := "medium"
			if grant.Right == "replicate-directory" {
				severity = "critical"
			} else if grant.Right == "local-admin" || grant.Right == "write-members" || assets[grant.Resource].Critical {
				severity = "high"
			}
			hash := sha256.Sum256([]byte(user.ID + "|" + key))
			assetName := assets[grant.Resource].Name
			out = append(out, domain.Finding{
				ID: fmt.Sprintf("DRIFT-%x", hash[:4]), UserID: user.ID, UserName: user.Name,
				Role: user.Role, Resource: grant.Resource, AssetName: assetName,
				Right: grant.Right, Severity: severity, GrantID: grant.ID,
				Path:   append(append([]string{}, path...), assetName+" · "+grant.Right),
				Reason: fmt.Sprintf("The %s role has no approved %s permission on %s in policy %s.", user.Role, grant.Right, assetName, s.PolicyVersion),
				Fix:    fmt.Sprintf("Review the membership path and remove or narrow grant %s; verify approved %s tasks still succeed.", grant.ID, user.Role),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return domain.SeverityPriority(out[i].Severity) > domain.SeverityPriority(out[j].Severity)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func FindUser(s domain.Snapshot, actor string) (domain.User, bool) {
	for _, user := range s.Users {
		if user.SID != "" && strings.EqualFold(user.SID, actor) {
			return user, true
		}
	}
	actor = strings.ToLower(actor)
	if _, after, ok := strings.Cut(actor, "\\"); ok {
		actor = after
	}
	actor, _, _ = strings.Cut(actor, "@")
	for _, user := range s.Users {
		if strings.EqualFold(user.ID, actor) || strings.EqualFold(user.Name, actor) {
			return user, true
		}
	}
	return domain.User{}, false
}

func ContextApplies(s domain.Snapshot, source string) bool {
	if len(s.EventSources) == 0 {
		return s.Source != "unconfigured" && s.Source != "" && s.Source == source
	}
	for _, allowed := range s.EventSources {
		if allowed == source {
			return true
		}
	}
	return false
}

func ApprovedChange(s domain.Snapshot, event domain.Event) bool {
	if !ContextApplies(s, event.Source) || event.Data["change_ticket"] == "" {
		return false
	}
	operator, operatorKnown := FindUser(s, event.Actor)
	target, targetKnown := FindUser(s, event.Target)
	if !operatorKnown || !targetKnown || operator.Role != "IT administrator" || target.Role != "IT administrator" {
		return false
	}
	for _, approval := range s.Approvals {
		if approval.Ticket == event.Data["change_ticket"] && strings.EqualFold(approval.Operator, operator.ID) && strings.EqualFold(approval.Target, target.ID) && strings.EqualFold(approval.Group, event.Data["group"]) && !event.Timestamp.Before(approval.ValidFrom) && !event.Timestamp.After(approval.ValidUntil) {
			return true
		}
	}
	return false
}
