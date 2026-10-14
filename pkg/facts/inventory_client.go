package facts

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/epithet-ssh/epithet/internal/servicehttp"
	"github.com/jtacoma/uritemplates"
)

// inventoryTemplates discovers only at the configured fact URL. A 4xx means a
// lookup-only provider. Transport/5xx/malformed successes remain failures; an
// ordinary successful OPTIONS without management relations is also lookup-only.
// Discovery is not cached: provider configuration changes take effect immediately.
func (c *ControlClient) inventoryTemplates(ctx context.Context) (map[string]*uritemplates.UriTemplate, error) {
	if c.inventory == nil {
		return nil, nil
	}
	resp, err := c.inventory.Do(ctx, servicehttp.Request{Method: "OPTIONS", URL: c.inventory.Endpoint()}, 65536)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if resp.Status >= 400 && resp.Status < 500 {
		return nil, nil
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return nil, fmt.Errorf("%w: inventory discovery HTTP %d", ErrUnavailable, resp.Status)
	}
	fields := resp.Header.Values("Link-Template")
	if len(fields) == 0 {
		return nil, nil
	}
	list, err := httpsfv.UnmarshalList(fields)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid Link-Template: %v", ErrUnavailable, err)
	}
	result := map[string]*uritemplates.UriTemplate{}
	for _, member := range list {
		item, ok := member.(httpsfv.Item)
		if !ok {
			return nil, fmt.Errorf("%w: Link-Template member must be a string", ErrUnavailable)
		}
		raw, ok := item.Value.(string)
		if !ok {
			return nil, fmt.Errorf("%w: Link-Template target must be a string", ErrUnavailable)
		}
		relation, ok := item.Params.Get("rel")
		if !ok {
			continue
		}
		rel, ok := relation.(string)
		if !ok {
			return nil, fmt.Errorf("%w: invalid template relation", ErrUnavailable)
		}
		for _, rel := range strings.Fields(rel) {
			if rel != InventoryRecordsRelation && rel != InventoryTokensRelation && rel != InventoryAuditRelation {
				continue
			}
			if _, ok := item.Params.Get("anchor"); ok {
				return nil, fmt.Errorf("%w: inventory templates must describe the fact endpoint", ErrUnavailable)
			}
			if result[rel] != nil {
				return nil, fmt.Errorf("%w: duplicate inventory relation", ErrUnavailable)
			}
			template, err := uritemplates.Parse(raw)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid URI template: %v", ErrUnavailable, err)
			}
			result[rel] = template
		}
	}
	if len(result) != 0 && len(result) != 3 {
		return nil, fmt.Errorf("%w: incomplete inventory relations", ErrUnavailable)
	}
	return result, nil
}

func (c *ControlClient) inventoryCall(ctx context.Context, auth Authorization, relation, method string, vars map[string]string, input any, match string) (*servicehttp.Response, error) {
	templates, err := c.inventoryTemplates(ctx)
	if err != nil {
		return nil, err
	}
	template := templates[relation]
	if template == nil {
		return nil, &ServiceError{Status: 404, Message: "provider does not support inventory management"}
	}
	values := map[string]interface{}{}
	for k, v := range vars {
		values[k] = v
	}
	expanded, err := template.Expand(values)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid inventory template: %v", ErrUnavailable, err)
	}
	target, err := c.inventory.Resolve(expanded)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
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
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if resp.Status < 200 || resp.Status >= 300 {
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(resp.Body, &failure)
		if failure.Error == "" {
			failure.Error = strings.TrimSpace(string(resp.Body))
		}
		return nil, &ServiceError{Status: resp.Status, Message: failure.Error}
	}
	return resp, nil
}
func inventoryRecordResult(resp *servicehttp.Response, err error) (*HostRecord, error) {
	if err != nil {
		return nil, err
	}
	if resp.Status != 200 && resp.Status != 201 {
		return nil, fmt.Errorf("%w: unexpected record status", ErrUnavailable)
	}
	var record InventoryRecord
	if err = json.Unmarshal(resp.Body, &record); err != nil || record.ID == "" || record.Status == "" {
		return nil, fmt.Errorf("%w: invalid inventory record", ErrUnavailable)
	}
	version, err := InventoryVersion(resp.Header.Get("ETag"))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	result := record.ControlRecord(version)
	return &result, nil
}
func (c *ControlClient) Enroll(ctx context.Context, proposal Proposal, token string) (*HostRecord, error) {
	return inventoryRecordResult(c.inventoryCall(ctx, Authorization{}, InventoryRecordsRelation, "POST", nil, InventoryCreate{Host: proposal.InventoryHost(), Token: token}, ""))
}
func (c *ControlClient) AddPattern(ctx context.Context, auth Authorization, proposal Proposal) (*HostRecord, error) {
	return inventoryRecordResult(c.inventoryCall(ctx, auth, InventoryRecordsRelation, "POST", nil, InventoryCreate{Host: proposal.InventoryHost()}, ""))
}
func (c *ControlClient) Host(ctx context.Context, auth Authorization, id string) (*HostRecord, error) {
	h, err := inventoryRecordResult(c.inventoryCall(ctx, auth, InventoryRecordsRelation, "GET", map[string]string{"id": id}, nil, ""))
	if err == nil && h.ID != id {
		return nil, fmt.Errorf("%w: inventory record identity mismatch", ErrUnavailable)
	}
	return h, err
}

// replaceHost adapts the agent's reviewed version to a whole PUT document. The
// read does not authorize a write: If-Match still binds PUT to the reviewed version,
// and the provider checks every precondition inside its atomic mutation.
func (c *ControlClient) replaceHost(ctx context.Context, auth Authorization, id string, version uint64, proposal *Proposal, status string) (*HostRecord, error) {
	h, err := c.Host(ctx, auth, id)
	if err != nil {
		return nil, err
	}
	if version == 0 || h.Revision != version {
		return nil, &ServiceError{Status: 412, Message: "record changed; reload before retrying"}
	}
	if proposal != nil {
		h.Proposal = *proposal
	}
	if status != "" {
		h.Status = status
	}
	return inventoryRecordResult(c.inventoryCall(ctx, auth, InventoryRecordsRelation, "PUT", map[string]string{"id": id}, h.InventoryRecord(), InventoryETag(version)))
}
func (c *ControlClient) EditHost(ctx context.Context, auth Authorization, id string, version uint64, p Proposal) (*HostRecord, error) {
	return c.replaceHost(ctx, auth, id, version, &p, "")
}
func (c *ControlClient) ApproveHost(ctx context.Context, auth Authorization, id string, version uint64) (*HostRecord, error) {
	return c.replaceHost(ctx, auth, id, version, nil, "active")
}
func (c *ControlClient) DenyHost(ctx context.Context, auth Authorization, id string, version uint64) (*HostRecord, error) {
	return c.replaceHost(ctx, auth, id, version, nil, "denied")
}
func (c *ControlClient) RemoveHost(ctx context.Context, auth Authorization, id string, version uint64) error {
	resp, err := c.inventoryCall(ctx, auth, InventoryRecordsRelation, "DELETE", map[string]string{"id": id}, nil, InventoryETag(version))
	return inventoryNoContent(resp, err)
}
func inventoryNoContent(resp *servicehttp.Response, err error) error {
	if err != nil {
		return err
	}
	if resp.Status != 204 {
		return fmt.Errorf("%w: expected 204", ErrUnavailable)
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
func (c *ControlClient) Hosts(ctx context.Context, auth Authorization, after string, limit int, pending bool) ([]HostRecord, error) {
	vars := inventoryPageVariables(after, limit)
	if pending {
		vars["pending"] = "true"
	}
	resp, err := c.inventoryCall(ctx, auth, InventoryRecordsRelation, "GET", vars, nil, "")
	if err != nil {
		return nil, err
	}
	var records []InventoryRecord
	if resp.Status != 200 || json.Unmarshal(resp.Body, &records) != nil || records == nil {
		return nil, fmt.Errorf("%w: invalid inventory page", ErrUnavailable)
	}
	result := make([]HostRecord, len(records))
	for i, h := range records {
		result[i] = h.ControlRecord(0)
	}
	return result, nil
}
func (c *ControlClient) CreateToken(ctx context.Context, auth Authorization, seconds int64) (*EnrollmentToken, error) {
	resp, err := c.inventoryCall(ctx, auth, InventoryTokensRelation, "POST", nil, InventoryTokenCreate{LifetimeSeconds: seconds}, "")
	if err != nil {
		return nil, err
	}
	var token InventoryToken
	if resp.Status != 201 || json.Unmarshal(resp.Body, &token) != nil || token.Token == "" || token.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("%w: invalid enrollment token", ErrUnavailable)
	}
	return &EnrollmentToken{ID: token.Token, ExpiresAt: token.ExpiresAt}, nil
}
func (c *ControlClient) RevokeToken(ctx context.Context, auth Authorization, token string) error {
	resp, err := c.inventoryCall(ctx, auth, InventoryTokensRelation, "DELETE", map[string]string{"token": token}, nil, "")
	return inventoryNoContent(resp, err)
}
func (c *ControlClient) HostAudit(ctx context.Context, auth Authorization, after uint64, limit int) ([]HostAuditEvent, error) {
	cursor := ""
	if after != 0 {
		cursor = strconv.FormatUint(after, 10)
	}
	resp, err := c.inventoryCall(ctx, auth, InventoryAuditRelation, "GET", inventoryPageVariables(cursor, limit), nil, "")
	if err != nil {
		return nil, err
	}
	var events []HostAuditEvent
	if resp.Status != 200 || json.Unmarshal(resp.Body, &events) != nil || events == nil {
		return nil, fmt.Errorf("%w: invalid audit page", ErrUnavailable)
	}
	return events, nil
}
