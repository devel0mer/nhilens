package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/devel0mer/nhilens/internal/model"
	"github.com/devel0mer/nhilens/internal/policy"
)

// GraphData contains Cytoscape.js-compatible nodes and edges representing identities,
// trust principals, policies, permissions boundaries, and user-to-key relationships.
type GraphData struct {
	Nodes                []GraphNode `json:"nodes"`
	Edges                []GraphEdge `json:"edges"`
	OmittedServiceLinked int         `json:"omitted_service_linked"`
}

// GraphNode wraps Cytoscape.js node data.
type GraphNode struct {
	Data GraphNodeData `json:"data"`
}

// GraphNodeData holds display and inspector attributes for a Cytoscape node.
type GraphNodeData struct {
	ID              string   `json:"id"`
	Label           string   `json:"label"`
	Kind            string   `json:"kind"` // role | user | key | trust | policy | boundary
	RiskTier        string   `json:"risk_tier"`
	ARN             string   `json:"arn,omitempty"`
	Score           float64  `json:"score,omitempty"`
	AgentLikelihood string   `json:"agent_likelihood,omitempty"`
	Owner           string   `json:"owner,omitempty"`
	Details         []string `json:"details,omitempty"`
}

// GraphEdge wraps Cytoscape.js edge data.
type GraphEdge struct {
	Data GraphEdgeData `json:"data"`
}

// GraphEdgeData holds source, target, and visual styling metadata for a Cytoscape edge.
type GraphEdgeData struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	Label    string `json:"label"`
	EdgeKind string `json:"edge_kind"` // trusts | has_policy | bounded_by | has_key
	Risky    bool   `json:"risky,omitempty"`
}

// BuildGraph creates a deduplicated identity-trust-policy graph for Cytoscape.js rendering.
// Unflagged AWS service-linked roles are omitted from the graph to keep visualization legible.
func BuildGraph(run *model.ScanRun) GraphData {
	if run == nil {
		return GraphData{}
	}

	nodesByID := make(map[string]GraphNode)
	edgesByID := make(map[string]GraphEdge)
	omittedSLR := 0

	addNode := func(n GraphNode) {
		if existing, ok := nodesByID[n.Data.ID]; ok {
			// Escalate risk tier on shared trust/policy nodes if any attached edge is risky.
			if riskTierRank(n.Data.RiskTier) > riskTierRank(existing.Data.RiskTier) {
				existing.Data.RiskTier = n.Data.RiskTier
				nodesByID[n.Data.ID] = existing
			}
			return
		}
		nodesByID[n.Data.ID] = n
	}
	addEdge := func(e GraphEdge) {
		if existing, ok := edgesByID[e.Data.ID]; ok {
			if e.Data.Risky {
				existing.Data.Risky = true
				edgesByID[e.Data.ID] = existing
			}
			return
		}
		edgesByID[e.Data.ID] = e
	}

	userNodeIDByARN := make(map[string]string)
	for _, ident := range run.Identities {
		if ident.Type == model.TypeUser {
			userNodeIDByARN[ident.ARN] = stableNodeID("id", ident.ID)
		}
	}

	for _, ident := range run.Identities {
		if ident.IsServiceLinkedRole && len(ident.Findings) == 0 {
			omittedSLR++
			continue
		}

		identNodeID := stableNodeID("id", ident.ID)
		ownerStr := "<none>"
		if ident.Owner != nil && strings.TrimSpace(*ident.Owner) != "" {
			ownerStr = *ident.Owner
		}

		details := buildIdentityNodeDetails(ident, ownerStr)
		label := ident.Name
		if ident.Type == model.TypeKey && ident.AccessKey != nil && ident.AccessKey.ParentUserName != "" {
			label = fmt.Sprintf("%s\n(%s)", ident.Name, ident.AccessKey.ParentUserName)
		}

		addNode(GraphNode{
			Data: GraphNodeData{
				ID:              identNodeID,
				Label:           label,
				Kind:            string(ident.Type),
				RiskTier:        riskTierFromIdentity(ident),
				ARN:             ident.ARN,
				Score:           ident.RiskScore,
				AgentLikelihood: string(ident.AgentLikelihood),
				Owner:           ownerStr,
				Details:         details,
			},
		})

		// User -> Access Key edge.
		if ident.Type == model.TypeKey && ident.AccessKey != nil {
			if parentNodeID, ok := userNodeIDByARN[ident.AccessKey.ParentUserARN]; ok {
				addEdge(GraphEdge{
					Data: GraphEdgeData{
						ID:       stableNodeID("edge", parentNodeID+"->"+identNodeID),
						Source:   parentNodeID,
						Target:   identNodeID,
						Label:    "key",
						EdgeKind: "has_key",
						Risky:    len(ident.Findings) > 0,
					},
				})
			}
		}

		hasLooseTrust := hasRuleFinding(ident, "R5")

		// Trust principal -> Role edges.
		for _, tp := range ident.TrustPrincipals {
			trustKey := tp.Type + ":" + tp.Value
			trustNodeID := stableNodeID("trust", trustKey)
			riskyTrust := tp.Type == "wildcard" || (hasLooseTrust && (tp.Type == "account" || tp.Type == "oidc" || tp.Type == "wildcard"))
			tier := "neutral"
			if riskyTrust {
				tier = "high"
				if tp.Type == "wildcard" {
					tier = "critical"
				}
			}

			trustDetails := []string{
				fmt.Sprintf("Principal type: %s", tp.Type),
				fmt.Sprintf("Principal: %s", tp.Value),
			}
			if len(tp.Actions) > 0 {
				trustDetails = append(trustDetails, fmt.Sprintf("Actions: %s", strings.Join(tp.Actions, ", ")))
			}

			addNode(GraphNode{
				Data: GraphNodeData{
					ID:       trustNodeID,
					Label:    shortTrustLabel(tp),
					Kind:     "trust",
					RiskTier: tier,
					Details:  trustDetails,
				},
			})

			addEdge(GraphEdge{
				Data: GraphEdgeData{
					ID:       stableNodeID("edge", trustNodeID+"->"+identNodeID),
					Source:   trustNodeID,
					Target:   identNodeID,
					Label:    "assumes",
					EdgeKind: "trusts",
					Risky:    riskyTrust,
				},
			})
		}

		// Identity -> Policy edges.
		for _, att := range ident.Policies {
			polKey := att.ARN
			if polKey == "" {
				// Inline policies are scoped to their owner identity (or group).
				if att.SourceGroup != "" {
					polKey = "group-inline:" + att.SourceGroup + ":" + att.Name
				} else {
					polKey = "inline:" + ident.ID + ":" + att.Name
				}
			}
			polNodeID := stableNodeID("pol", polKey)
			isWildcard := policyAttachmentHasWildcard(att)
			tier := "neutral"
			if isWildcard {
				tier = "critical"
			}

			polDetails := []string{fmt.Sprintf("Kind: %s", att.Kind)}
			if att.ARN != "" {
				polDetails = append(polDetails, fmt.Sprintf("ARN: %s", att.ARN))
			}
			if att.SourceGroup != "" {
				polDetails = append(polDetails, fmt.Sprintf("Inherited via group: %s", att.SourceGroup))
			}
			if isWildcard {
				polDetails = append(polDetails, "Grants wildcard admin permissions (Action:* Resource:* or AdministratorAccess)")
			}

			label := att.Name
			if label == "" {
				label = shortARNName(att.ARN)
			}

			addNode(GraphNode{
				Data: GraphNodeData{
					ID:       polNodeID,
					Label:    label,
					Kind:     "policy",
					RiskTier: tier,
					ARN:      att.ARN,
					Details:  polDetails,
				},
			})

			edgeLabel := att.Kind
			if att.SourceGroup != "" {
				edgeLabel = "group:" + att.SourceGroup
			}
			addEdge(GraphEdge{
				Data: GraphEdgeData{
					ID:       stableNodeID("edge", identNodeID+"->"+polNodeID+":"+edgeLabel),
					Source:   identNodeID,
					Target:   polNodeID,
					Label:    edgeLabel,
					EdgeKind: "has_policy",
					Risky:    isWildcard,
				},
			})
		}

		// Identity -> Permissions Boundary edge (visibility).
		if strings.TrimSpace(ident.PermissionsBoundaryARN) != "" {
			bNodeID := stableNodeID("boundary", ident.PermissionsBoundaryARN)
			addNode(GraphNode{
				Data: GraphNodeData{
					ID:       bNodeID,
					Label:    "Boundary: " + shortARNName(ident.PermissionsBoundaryARN),
					Kind:     "boundary",
					RiskTier: "neutral",
					ARN:      ident.PermissionsBoundaryARN,
					Details: []string{
						"Attached IAM Permissions Boundary",
						"ARN: " + ident.PermissionsBoundaryARN,
						"Note: nhilens intersects boundaries at the action level across R1, R6, and R7; resource and session policies are not evaluated.",
					},
				},
			})
			addEdge(GraphEdge{
				Data: GraphEdgeData{
					ID:       stableNodeID("edge", identNodeID+"->"+bNodeID),
					Source:   identNodeID,
					Target:   bNodeID,
					Label:    "boundary",
					EdgeKind: "bounded_by",
				},
			})
		}
	}

	nodes := make([]GraphNode, 0, len(nodesByID))
	for _, n := range nodesByID {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Data.ID < nodes[j].Data.ID
	})

	edges := make([]GraphEdge, 0, len(edgesByID))
	for _, e := range edgesByID {
		edges = append(edges, e)
	}
	sort.Slice(edges, func(i, j int) bool {
		return edges[i].Data.ID < edges[j].Data.ID
	})

	return GraphData{
		Nodes:                nodes,
		Edges:                edges,
		OmittedServiceLinked: omittedSLR,
	}
}

func buildIdentityNodeDetails(ident model.Identity, owner string) []string {
	agentLabel := string(ident.AgentLikelihood)
	if ident.AgentConfidence > 0 {
		agentLabel = fmt.Sprintf("%s (%d%%)", ident.AgentLikelihood, ident.AgentConfidence)
	}
	if ident.WorkloadKind != "" {
		agentLabel += " {" + ident.WorkloadKind + "}"
	}
	if ident.AgentProfile != "" {
		agentLabel += " [" + ident.AgentProfile + "]"
	}

	details := []string{
		fmt.Sprintf("Type: %s", ident.Type),
		fmt.Sprintf("ARN: %s", ident.ARN),
		fmt.Sprintf("Risk score: %.1f / 10 (raw %.1f)", ident.RiskScore, ident.RawRiskPoints),
		fmt.Sprintf("Agent likelihood (heuristic): %s", agentLabel),
		fmt.Sprintf("Owner: %s", owner),
	}
	if ident.ScoreExplanation != "" {
		details = append(details, "Why this score: "+ident.ScoreExplanation)
	}
	if len(ident.DataGaps) > 0 {
		details = append(details, "Coverage gaps (partial data): "+strings.Join(ident.DataGaps, ", "))
	}
	if len(ident.AIServices) > 0 {
		details = append(details, "AI/LLM services: "+strings.Join(ident.AIServices, ", "))
	}
	if len(ident.ObservedUserAgents) > 0 {
		details = append(details, "CloudTrail userAgents: "+strings.Join(ident.ObservedUserAgents, "; "))
	}
	if ident.Activity30d != nil && ident.Activity30d.TotalEvents > 0 {
		details = append(details, "30d activity: "+formatActivitySummary(ident.Activity30d))
	}
	if ident.PermissionsBoundaryARN != "" {
		details = append(details, fmt.Sprintf("Permissions boundary: %s", ident.PermissionsBoundaryARN))
	}
	if len(ident.AgentReasons) > 0 {
		details = append(details, "Agent signals: "+strings.Join(ident.AgentReasons, "; "))
	}
	if len(ident.Findings) > 0 {
		fids := make([]string, 0, len(ident.Findings))
		for _, f := range ident.Findings {
			fids = append(fids, fmt.Sprintf("%s (%s)", f.RuleID, f.Severity))
		}
		details = append(details, "Findings: "+strings.Join(fids, ", "))
	}
	if len(ident.SourceIPs) > 0 {
		details = append(details, "Observed IPs (best-effort): "+strings.Join(ident.SourceIPs, ", "))
	}
	if len(ident.RecentEventNames) > 0 {
		details = append(details, "Recent CloudTrail actions: "+strings.Join(ident.RecentEventNames, ", "))
	}
	return details
}

func policyAttachmentHasWildcard(att model.PolicyAttachment) bool {
	if policy.IsAdministratorAccessARN(att.ARN) {
		return true
	}
	if att.Parsed == nil {
		return false
	}
	for _, stmt := range att.Parsed.Statements {
		if stmt.Effect == "Allow" && policy.ContainsWildcardAction(stmt.Actions) && policy.ContainsWildcardResource(stmt.Resources) {
			return true
		}
	}
	return false
}

func hasRuleFinding(ident model.Identity, ruleID string) bool {
	for _, f := range ident.Findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func riskTierFromIdentity(ident model.Identity) string {
	switch {
	case ident.RiskScore >= 7.0:
		return "critical"
	case ident.RiskScore >= 4.0:
		return "high"
	case ident.RiskScore >= 2.0:
		return "medium"
	case ident.RiskScore > 0:
		return "low"
	default:
		return "clean"
	}
}

func riskTierRank(tier string) int {
	switch tier {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "clean":
		return 1
	default:
		return 0
	}
}

func shortTrustLabel(tp model.TrustPrincipal) string {
	if tp.Type == "wildcard" {
		return "Principal: *"
	}
	if tp.Type == "oidc" {
		if idx := strings.Index(tp.Value, ":oidc-provider/"); idx >= 0 {
			return "OIDC: " + tp.Value[idx+len(":oidc-provider/"):]
		}
		return "OIDC: " + tp.Value
	}
	if tp.Type == "account" {
		if acct := policy.ExtractAccountID(tp.Value); acct != "" {
			return "AWS: " + acct
		}
	}
	return tp.Value
}

func shortARNName(arn string) string {
	if idx := strings.LastIndexByte(arn, '/'); idx >= 0 && idx+1 < len(arn) {
		return arn[idx+1:]
	}
	return arn
}

func stableNodeID(prefix, raw string) string {
	sum := sha256.Sum256([]byte(prefix + ":" + raw))
	return prefix + "_" + hex.EncodeToString(sum[:8])
}
