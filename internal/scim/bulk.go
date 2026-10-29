package scim

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// Bulk (RFC 7644 §3.7): up to MaxOperations operations and MaxPayloadSize
// bytes, applied in order (not atomically, as the RFC allows); a POST names
// a bulkId that later operations may reference as "bulkId:<id>";
// failOnErrors stops after that many errors.

type bulkOp struct {
	Method  string          `json:"method"`
	BulkID  string          `json:"bulkId,omitempty"`
	Version string          `json:"version,omitempty"`
	Path    string          `json:"path"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (s *Server) bulk(w http.ResponseWriter, r *http.Request, c call) {
	var req struct {
		Schemas      []string `json:"schemas"`
		FailOnErrors *int     `json:"failOnErrors"`
		Operations   []bulkOp `json:"Operations"`
	}
	if err := decodeJSON(r.Body, &req); err != nil {
		writeErr(w, err)
		return
	}
	if !containsFold(req.Schemas, SchemaBulkReq) {
		writeErr(w, bad("invalidSyntax", "schemas must be [%q]", SchemaBulkReq))
		return
	}
	if len(req.Operations) > MaxOperations {
		writeErr(w, &Error{Status: http.StatusRequestEntityTooLarge,
			Detail: "at most " + strconv.Itoa(MaxOperations) + " operations per request"})
		return
	}
	ids := map[string]string{} // bulkId -> created id
	var results []any
	errs := 0
	for _, op := range req.Operations {
		if req.FailOnErrors != nil && *req.FailOnErrors > 0 && errs >= *req.FailOnErrors {
			break
		}
		res := map[string]any{"method": strings.ToUpper(op.Method)}
		if op.BulkID != "" {
			res["bulkId"] = op.BulkID
		}
		status, doc, err := s.bulkOne(r, c, op, ids)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) {
				if errors.Is(err, errUnauthorized) {
					e = &Error{Status: http.StatusUnauthorized, Detail: "the token is no longer valid"}
				} else {
					if s.Logger != nil {
						s.Logger.Error("SCIM bulk", "method", op.Method, "path", op.Path, "error", err.Error())
					}
					e = &Error{Status: http.StatusInternalServerError, Detail: "internal error"}
				}
			}
			errs++
			res["status"] = strconv.Itoa(e.Status)
			res["response"] = errBody(e)
			results = append(results, res)
			continue
		}
		res["status"] = strconv.Itoa(status)
		if doc != nil {
			meta := doc["meta"].(map[string]any)
			res["location"] = meta["location"]
			res["version"] = meta["version"]
		}
		results = append(results, res)
	}
	if results == nil {
		results = []any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"schemas": []string{SchemaBulkResp}, "Operations": results})
}

func (s *Server) bulkOne(r *http.Request, c call, op bulkOp, ids map[string]string) (int, map[string]any, error) {
	ctx := r.Context()
	method := strings.ToUpper(op.Method)
	p, err := resolveRefs(op.Path, ids)
	if err != nil {
		return 0, nil, err
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) == 0 || (parts[0] != "Users" && parts[0] != "Groups") || len(parts) > 2 {
		return 0, nil, bad("invalidPath", "path must be /Users, /Groups or a resource under them")
	}
	k := userKind
	if parts[0] == "Groups" {
		k = groupKind
	}
	var id string
	if len(parts) == 2 {
		if !uuidRE.MatchString(parts[1]) {
			return 0, nil, &Error{Status: http.StatusNotFound, Detail: "no such resource"}
		}
		id = strings.ToLower(parts[1])
	}
	ifVersion, ok := parseETag(op.Version)
	if !ok {
		return 0, nil, bad("invalidVers", "version is not one this server issued")
	}
	var data any
	if len(op.Data) > 0 {
		raw, err := resolveRefs(string(op.Data), ids)
		if err != nil {
			return 0, nil, err
		}
		if err := json.Unmarshal([]byte(raw), &data); err != nil {
			return 0, nil, bad("invalidSyntax", "data: %v", err)
		}
	}
	switch {
	case method == http.MethodPost && id == "":
		if op.BulkID == "" {
			return 0, nil, bad("invalidSyntax", "a POST needs a bulkId")
		}
		body, ok := data.(map[string]any)
		if !ok {
			return 0, nil, bad("invalidSyntax", "data must be the resource")
		}
		doc, err := s.create(ctx, c, k, body)
		if err != nil {
			return 0, nil, err
		}
		ids[op.BulkID] = doc["id"].(string)
		return http.StatusCreated, doc, nil
	case method == http.MethodPut && id != "":
		body, ok := data.(map[string]any)
		if !ok {
			return 0, nil, bad("invalidSyntax", "data must be the resource")
		}
		doc, err := s.replace(ctx, c, k, id, ifVersion, body)
		return http.StatusOK, doc, err
	case method == http.MethodPatch && id != "":
		var body struct {
			Schemas    []string  `json:"schemas"`
			Operations []PatchOp `json:"Operations"`
		}
		b, _ := json.Marshal(data)
		if err := json.Unmarshal(b, &body); err != nil || !containsFold(body.Schemas, SchemaPatch) {
			return 0, nil, bad("invalidSyntax", "data must be a PatchOp request")
		}
		doc, err := s.patch(ctx, c, k, id, ifVersion, body.Operations)
		return http.StatusOK, doc, err
	case method == http.MethodDelete && id != "":
		return http.StatusNoContent, nil, s.Store.remove(ctx, c.th, k, id, ifVersion)
	}
	return 0, nil, bad("invalidSyntax", "%s %s is not a bulk operation", method, p)
}

// resolveRefs replaces "bulkId:<id>" with the id the earlier POST created;
// a reference to an operation not yet done is refused.
func resolveRefs(s string, ids map[string]string) (string, error) {
	for {
		i := strings.Index(s, "bulkId:")
		if i < 0 {
			return s, nil
		}
		j := i + len("bulkId:")
		for j < len(s) && (s[j] == '-' || s[j] == '_' || s[j] == '.' || (s[j] >= '0' && s[j] <= '9') ||
			(s[j]|0x20 >= 'a' && s[j]|0x20 <= 'z')) {
			j++
		}
		ref := s[i+len("bulkId:") : j]
		id, ok := ids[ref]
		if !ok {
			return "", &Error{Status: http.StatusConflict, ScimType: "invalidValue", Detail: "bulkId " + ref + " is not a completed operation"}
		}
		s = s[:i] + id + s[j:]
	}
}
