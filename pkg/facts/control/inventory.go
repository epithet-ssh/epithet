package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/epithet-ssh/epithet/internal/servicehttp"
	"github.com/epithet-ssh/epithet/pkg/facts"
	"github.com/jtacoma/uritemplates"
)

// inventoryTemplates discovers only at the configured fact URL. A 4xx means a
// lookup-only provider. Transport/5xx/malformed successes remain failures; an
// ordinary successful OPTIONS without management relations is also lookup-only.
// Discovery is not cached: provider configuration changes take effect immediately.
func (c *Server) inventoryTemplates(ctx context.Context) (map[string]*uritemplates.UriTemplate, error) {
	if c.inventory == nil {
		return nil, nil
	}
	resp, err := c.inventory.Do(ctx, servicehttp.Request{Method: "OPTIONS", URL: c.inventory.Endpoint()}, 65536)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", facts.ErrUnavailable, err)
	}
	if resp.Status >= 400 && resp.Status < 500 {
		return nil, nil
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return nil, fmt.Errorf("%w: inventory discovery HTTP %d", facts.ErrUnavailable, resp.Status)
	}
	fields := resp.Header.Values("Link-Template")
	if len(fields) == 0 {
		return nil, nil
	}
	list, err := httpsfv.UnmarshalList(fields)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid Link-Template: %v", facts.ErrUnavailable, err)
	}
	result := map[string]*uritemplates.UriTemplate{}
	for _, member := range list {
		item, ok := member.(httpsfv.Item)
		if !ok {
			return nil, fmt.Errorf("%w: Link-Template member must be a string", facts.ErrUnavailable)
		}
		raw, ok := item.Value.(string)
		if !ok {
			return nil, fmt.Errorf("%w: Link-Template target must be a string", facts.ErrUnavailable)
		}
		relation, ok := item.Params.Get("rel")
		if !ok {
			continue
		}
		rel, ok := relation.(string)
		if !ok {
			return nil, fmt.Errorf("%w: invalid template relation", facts.ErrUnavailable)
		}
		for _, rel := range strings.Fields(rel) {
			if rel != facts.InventoryRecordsRelation && rel != facts.InventoryTokensRelation && rel != facts.InventoryAuditRelation {
				continue
			}
			if _, ok := item.Params.Get("anchor"); ok {
				return nil, fmt.Errorf("%w: inventory templates must describe the fact endpoint", facts.ErrUnavailable)
			}
			if result[rel] != nil {
				return nil, fmt.Errorf("%w: duplicate inventory relation", facts.ErrUnavailable)
			}
			template, err := uritemplates.Parse(raw)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid URI template: %v", facts.ErrUnavailable, err)
			}
			result[rel] = template
		}
	}
	if len(result) != 0 && len(result) != 3 {
		return nil, fmt.Errorf("%w: incomplete inventory relations", facts.ErrUnavailable)
	}
	return result, nil
}

func (c *Server) inventoryCall(ctx context.Context, auth authorization, relation, method string, vars map[string]string, input any, match string) (*servicehttp.Response, error) {
	templates, err := c.inventoryTemplates(ctx)
	if err != nil {
		return nil, err
	}
	template := templates[relation]
	if template == nil {
		return nil, &facts.ServiceError{Status: 404, Message: "provider does not support inventory management"}
	}
	values := map[string]interface{}{}
	for k, v := range vars {
		values[k] = v
	}
	expanded, err := template.Expand(values)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid inventory template: %v", facts.ErrUnavailable, err)
	}
	target, err := c.inventory.Resolve(expanded)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", facts.ErrUnavailable, err)
	}
	var body []byte
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return nil, err
		}
	}
	contentType := ""
	if body != nil {
		contentType = "application/json"
	}
	resp, err := c.inventory.Do(ctx, servicehttp.Request{Method: method, URL: target.String(), Body: body, Actor: auth.Actor, IfMatch: match, ContentType: contentType}, controlResponseLimit)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", facts.ErrUnavailable, err)
	}
	if resp.Status < 200 || resp.Status >= 300 {
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(resp.Body, &failure)
		if failure.Error == "" {
			failure.Error = strings.TrimSpace(string(resp.Body))
		}
		return nil, &facts.ServiceError{Status: resp.Status, Message: failure.Error}
	}
	return resp, nil
}
func inventoryRecordResult(resp *servicehttp.Response, err error) (*facts.HostRecord, error) {
	if err != nil {
		return nil, err
	}
	if resp.Status != 200 && resp.Status != 201 {
		return nil, fmt.Errorf("%w: unexpected record status", facts.ErrUnavailable)
	}
	var record facts.InventoryRecord
	if err = json.Unmarshal(resp.Body, &record); err != nil || record.ID == "" || record.Status == "" {
		return nil, fmt.Errorf("%w: invalid inventory record", facts.ErrUnavailable)
	}
	version, err := facts.InventoryVersion(resp.Header.Get("ETag"))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", facts.ErrUnavailable, err)
	}
	result := controlRecord(record, version)
	return &result, nil
}
func (c *Server) enroll(ctx context.Context, id string, proposal facts.InventoryInput, token string) (*facts.HostRecord, error) {
	return inventoryRecordResult(c.inventoryCall(ctx, authorization{}, facts.InventoryRecordsRelation, "PUT", map[string]string{"id": id}, facts.InventoryCreate{Host: inventoryHost(proposal), Token: token}, ""))
}
func (c *Server) addHost(ctx context.Context, auth authorization, proposal facts.InventoryInput) (*facts.HostRecord, error) {
	return inventoryRecordResult(c.inventoryCall(ctx, auth, facts.InventoryRecordsRelation, "POST", nil, facts.InventoryCreate{Host: inventoryHost(proposal)}, ""))
}
func (c *Server) host(ctx context.Context, auth authorization, id string) (*facts.HostRecord, error) {
	h, err := inventoryRecordResult(c.inventoryCall(ctx, auth, facts.InventoryRecordsRelation, "GET", map[string]string{"id": id}, nil, ""))
	if err == nil && h.ID != id {
		return nil, fmt.Errorf("%w: inventory record identity mismatch", facts.ErrUnavailable)
	}
	return h, err
}

// replaceHost adapts the agent's reviewed version to a whole PUT document. The
// read does not authorize a write: If-Match still binds PUT to the reviewed version,
// and the provider checks every precondition inside its atomic mutation.
func (c *Server) replaceHost(ctx context.Context, auth authorization, id string, expectedVersion string, proposal *facts.InventoryInput, status string) (*facts.HostRecord, error) {
	h, err := c.host(ctx, auth, id)
	if err != nil {
		return nil, err
	}
	if h.Version != expectedVersion {
		return nil, &facts.ServiceError{Status: 412, Message: "record changed; reload before retrying"}
	}
	if proposal != nil {
		h.Host = *proposal
	}
	if status != "" {
		h.Status = status
	}
	return inventoryRecordResult(c.inventoryCall(ctx, auth, facts.InventoryRecordsRelation, "PUT", map[string]string{"id": id}, inventoryRecord(*h), facts.InventoryETag(expectedVersion)))
}
func (c *Server) editHost(ctx context.Context, auth authorization, id string, expectedVersion string, p facts.InventoryInput) (*facts.HostRecord, error) {
	return c.replaceHost(ctx, auth, id, expectedVersion, &p, "")
}
func (c *Server) approveHost(ctx context.Context, auth authorization, id string, expectedVersion string) (*facts.HostRecord, error) {
	return c.replaceHost(ctx, auth, id, expectedVersion, nil, "active")
}
func (c *Server) denyHost(ctx context.Context, auth authorization, id string, expectedVersion string) (*facts.HostRecord, error) {
	return c.replaceHost(ctx, auth, id, expectedVersion, nil, "denied")
}
func (c *Server) removeHost(ctx context.Context, auth authorization, id string, expectedVersion string) error {
	resp, err := c.inventoryCall(ctx, auth, facts.InventoryRecordsRelation, "DELETE", map[string]string{"id": id}, nil, facts.InventoryETag(expectedVersion))
	return inventoryNoContent(resp, err)
}
func inventoryNoContent(resp *servicehttp.Response, err error) error {
	if err != nil {
		return err
	}
	if resp.Status != 204 {
		return fmt.Errorf("%w: expected 204", facts.ErrUnavailable)
	}
	return nil
}
func inventoryPageVariables(after string, limit int) map[string]string {
	vars := map[string]string{}
	if after != "" {
		vars["after"] = after
	}
	if limit != 0 {
		vars["limit"] = strconv.Itoa(limit)
	}
	return vars
}

// Hosts returns ID-ordered records. List results have no version: fetch the
// selected item before editing/reviewing to obtain its ETag.
func (c *Server) hosts(ctx context.Context, auth authorization, after string, limit int, pending bool) ([]facts.HostRecord, error) {
	vars := inventoryPageVariables(after, limit)
	if pending {
		vars["pending"] = "true"
	}
	resp, err := c.inventoryCall(ctx, auth, facts.InventoryRecordsRelation, "GET", vars, nil, "")
	if err != nil {
		return nil, err
	}
	var records []facts.InventoryRecord
	if resp.Status != 200 || json.Unmarshal(resp.Body, &records) != nil || records == nil {
		return nil, fmt.Errorf("%w: invalid inventory page", facts.ErrUnavailable)
	}
	result := make([]facts.HostRecord, len(records))
	for i, h := range records {
		result[i] = controlRecord(h, "")
	}
	return result, nil
}
func (c *Server) createToken(ctx context.Context, auth authorization, seconds int64) (*facts.EnrollmentToken, error) {
	resp, err := c.inventoryCall(ctx, auth, facts.InventoryTokensRelation, "POST", nil, facts.InventoryTokenCreate{LifetimeSeconds: seconds}, "")
	if err != nil {
		return nil, err
	}
	var token facts.InventoryToken
	if resp.Status != 201 || json.Unmarshal(resp.Body, &token) != nil || token.Token == "" || token.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("%w: invalid enrollment token", facts.ErrUnavailable)
	}
	return &facts.EnrollmentToken{ID: token.Token, ExpiresAt: token.ExpiresAt}, nil
}
func (c *Server) revokeToken(ctx context.Context, auth authorization, token string) error {
	resp, err := c.inventoryCall(ctx, auth, facts.InventoryTokensRelation, "DELETE", map[string]string{"token": token}, nil, "")
	return inventoryNoContent(resp, err)
}
func (c *Server) hostAudit(ctx context.Context, auth authorization, cursor string, limit int) (*facts.AuditPage[facts.HostAuditEvent], error) {
	vars := map[string]string{}
	if cursor != "" {
		vars["cursor"] = cursor
	}
	if limit != 0 {
		vars["limit"] = strconv.Itoa(limit)
	}
	resp, err := c.inventoryCall(ctx, auth, facts.InventoryAuditRelation, "GET", vars, nil, "")
	if err != nil {
		return nil, err
	}
	var page facts.AuditPage[facts.HostAuditEvent]
	if resp.Status != 200 || json.Unmarshal(resp.Body, &page) != nil || page.Events == nil {
		return nil, fmt.Errorf("%w: invalid audit page", facts.ErrUnavailable)
	}
	return &page, nil
}

func inventoryHost(p facts.InventoryInput) *facts.InventoryHost {
	if p.Names == nil && p.Labels == nil && p.Accounts == nil && p.PrincipalMode == "" && p.Realm == "" {
		return nil
	}
	return &facts.InventoryHost{Name: p.Names, Attributes: p.Labels, Accounts: p.Accounts, Principal: facts.InventoryPrincipal{Mode: p.PrincipalMode, Realm: p.Realm}}
}
func controlInput(p *facts.InventoryHost) facts.InventoryInput {
	if p == nil {
		return facts.InventoryInput{}
	}
	return facts.InventoryInput{Names: p.Name, Labels: p.Attributes, Accounts: p.Accounts, PrincipalMode: p.Principal.Mode, Realm: p.Principal.Realm}
}
func inventoryRecord(h facts.HostRecord) facts.InventoryRecord {
	return facts.InventoryRecord{ID: h.ID, Status: h.Status, Host: inventoryHost(h.Host), CreatedAt: h.CreatedAt, UpdatedAt: h.UpdatedAt}
}
func controlRecord(h facts.InventoryRecord, version string) facts.HostRecord {
	return facts.HostRecord{ID: h.ID, Version: version, Status: h.Status, Host: controlInput(h.Host), CreatedAt: h.CreatedAt, UpdatedAt: h.UpdatedAt}
}
