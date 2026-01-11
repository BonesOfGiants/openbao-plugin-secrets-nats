package natsbackend

import (
	"context"
	"fmt"
	"iter"
	"slices"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/shimtx"
	"github.com/nats-io/jwt/v2"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

var (
	rootParamsKeys = []string{"name", "subject", "account", "token", "local_subject", "type", "share", "allow_trace"}
)

type accountImportEntry struct {
	accountImportId

	Imports jwt.Imports `json:"imports"`
}

type accountImportId struct {
	op   string
	acc  string
	name string
}

func NewAccountImport(id accountImportId) *accountImportEntry {
	return &accountImportEntry{
		accountImportId: id,
	}
}

func NewAccountImportWithParams(id accountImportId, imports jwt.Imports) *accountImportEntry {
	return &accountImportEntry{
		accountImportId: id,

		Imports: imports,
	}
}

func AccountImportId(op, acc, name string) accountImportId {
	return accountImportId{
		op:   op,
		acc:  acc,
		name: name,
	}
}

func AccountImportIdField(d *framework.FieldData) accountImportId {
	return accountImportId{
		op:   d.Get("operator").(string),
		acc:  d.Get("import_account").(string),
		name: d.Get("import_name").(string),
	}
}

func (id accountImportId) operatorId() operatorId {
	return OperatorId(id.op)
}

func (id accountImportId) accountId() accountId {
	return AccountId(id.op, id.acc)
}

func (id accountImportId) configPath() string {
	return accountImportsPathPrefix + id.op + "/" + id.acc + "/" + id.name
}

func pathConfigAccountImport(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: accountImportsPathPrefix + operatorRegex + "/" + framework.GenericNameRegex("import_account") + "/" + framework.GenericNameRegex("import_name") + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator":       operatorField,
				"import_account": accountField,
				"import_name": {
					Type:        framework.TypeString,
					Description: `The name given to this collection of imports.`,
					Required:    true,
				},
				"imports": {
					Type:        framework.TypeSlice,
					Description: "A list of import definitions to define on the account. At least one import must be specified.",
					Required:    false,
				},
				"name": {
					Type:        framework.TypeString,
					Description: "The name of the import.",
					Required:    false,
				},
				"subject": {
					Type:        framework.TypeString,
					Description: "The subject being imported.",
					Required:    false,
				},
				"account": {
					Type:        framework.TypeString,
					Description: "The subject being imported.",
					Required:    false,
				},
				"token": {
					Type:        framework.TypeString,
					Description: "An optional activation token. Required for imports of private exports.",
					Required:    false,
				},
				"local_subject": {
					Type:        framework.TypeString,
					Description: "An optional mapping to a different subject in the account.",
					Required:    false,
				},
				"type": {
					Type:          framework.TypeString,
					AllowedValues: []any{"stream", "service"},
					Description:   "Describes the type of the import. Valid values are `stream` and `service`.",
					Required:      false,
				},
				"share": {
					Type:        framework.TypeBool,
					Description: "If importing a service, indicates if the import supports latency tracking.",
					Required:    false,
				},
				"allow_trace": {
					Type:        framework.TypeBool,
					Description: "If importing a stream, indicates if the import allows message tracing.",
					Required:    false,
				},
			},
			ExistenceCheck: b.pathAccountImportExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathAccountImportCreateUpdate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathAccountImportCreateUpdate,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathAccountImportRead,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathAccountImportDelete,
				},
			},
			HelpSynopsis:    `Manages externally defined imports for accounts.`,
			HelpDescription: `Create and manage imports that will be appended to account claims when generating account jwts.`,
		},
		{
			Pattern: accountImportsPathPrefix + operatorRegex + "/" + accountRegex + "/?$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"after":    afterField,
				"limit":    limitField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathAccountImportList,
				},
			},
			HelpSynopsis: "List account import configs.",
		},
	}
}

func (b *backend) AccountImport(ctx context.Context, storage logical.Storage, id accountImportId) (*accountImportEntry, error) {
	imp, err := getFromStorage[accountImportEntry](ctx, storage, id.configPath())
	if imp != nil {
		imp.accountImportId = id
	}
	return imp, err
}

func (b *backend) pathAccountImportCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := AccountImportIdField(d)

	// use the nkey as the existence check since we
	// need to use the public key for validation
	nkey, err := b.Nkey(ctx, req.Storage, id.accountId())
	if err != nil {
		return nil, err
	}
	if nkey == nil {
		return logical.ErrorResponse("account %q does not exist", id.acc), nil
	}

	jwtDirty := false
	accImport, err := b.AccountImport(ctx, req.Storage, id)
	if err != nil {
		return nil, err
	}
	if accImport == nil {
		accImport = NewAccountImport(id)
		jwtDirty = true
	}

	if importsRaw, ok := d.GetOk("imports"); ok {
		importsRaw, ok := importsRaw.([]any)
		if !ok {
			return logical.ErrorResponse("imports must be an array, got %T", importsRaw), nil
		}

		for v := range d.Raw {
			if slices.Contains(rootParamsKeys, v) {
				return logical.ErrorResponse("may not specify imports array along with root-level import parameters"), nil
			}
		}

		jwtDirty = jwtDirty || (len(importsRaw) != len(accImport.Imports))

		imports := accImport.Imports
		if imports == nil {
			imports = make(jwt.Imports, 0, len(importsRaw))
		}
		for i, v := range importsRaw {
			if importRaw, ok := v.(map[string]any); ok {
				var imp *jwt.Import
				if i < imports.Len() {
					imp = imports[i]
				} else {
					imp = &jwt.Import{}
					imports = append(imports, imp)
					jwtDirty = true
				}

				_, importDirty, err := updateImportParams(importRaw, imp)
				if err != nil {
					return logical.ErrorResponse("import[%d]: %w", i, err), nil
				}

				jwtDirty = jwtDirty || importDirty
			} else {
				return logical.ErrorResponse("import must be a map, got %T", v), nil
			}
		}

		accImport.Imports = imports
	} else {
		var imp *jwt.Import
		if len(accImport.Imports) > 0 {
			imp = accImport.Imports[0]
		} else {
			imp = &jwt.Import{}
		}

		hasParams, importDirty, err := updateImportParams(d.Raw, imp)
		if err != nil {
			return logical.ErrorResponse("import[0]: %w", err), nil
		}

		if hasParams {
			switch {
			case len(accImport.Imports) > 1:
				return logical.ErrorResponse("cannot specify root-level parameters on an account import with more than one import claim"), nil
			case len(accImport.Imports) == 1:
				accImport.Imports[0] = imp
			default:
				accImport.Imports = jwt.Imports{imp}
			}
		}

		jwtDirty = jwtDirty || importDirty
	}

	if len(accImport.Imports) == 0 {
		return logical.ErrorResponse("must define at least one import"), nil
	}

	publicKey, err := nkey.publicKey()
	if err != nil {
		return nil, err
	}

	var vr jwt.ValidationResults
	accImport.Imports.Validate(publicKey, &vr)

	errors := vr.Errors()
	if len(errors) > 0 {
		errResp := logical.ErrorResponse("validation error: %s", sprintErrors(errors))
		errResp.Warnings = append(errResp.Warnings, vr.Warnings()...)

		return errResp, nil
	}

	err = storeInStorage(ctx, req.Storage, accImport.configPath(), accImport)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{}
	resp.Warnings = append(resp.Warnings, vr.Warnings()...)

	if jwtDirty {
		warnings, err := b.issueAndSaveAccountJWT(ctx, req.Storage, id.accountId())
		if err != nil {
			return nil, fmt.Errorf("failed to encode account jwt: %w", err)
		}

		for _, v := range warnings {
			resp.AddWarning(fmt.Sprintf("while reissuing jwt for account %q: %s", id.acc, v))
		}
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	if jwtDirty {
		accountSync, err := b.getAccountSync(ctx, req.Storage, id.operatorId())
		if err != nil {
			b.Logger().Warn("failed to retrieve account sync", "operator", id.op, "account", id.acc, "error", err)
			resp.AddWarning(fmt.Sprintf("unable to sync jwt for account %q: %s", id.acc, err))
		} else if accountSync != nil {
			err := b.syncAccountUpdate(ctx, req.Storage, accountSync, id.accountId())
			if err != nil {
				b.Logger().Warn("failed to sync account", "operator", id.op, "account", id.acc, "error", err)
				resp.AddWarning(fmt.Sprintf("unable to sync jwt for account %q: %s", id.acc, err))
			}
		}
	}

	return resp, nil
}

func (b *backend) pathAccountImportRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	impConfig, err := b.AccountImport(ctx, req.Storage, AccountImportIdField(d))
	if err != nil || impConfig == nil {
		return nil, err
	}

	data := map[string]any{}

	if impConfig.Imports != nil {
		imports := make([]map[string]any, len(impConfig.Imports))
		for i, imp := range impConfig.Imports {
			impData := map[string]any{}

			if imp.Name != "" {
				impData["name"] = imp.Name
			}
			if imp.Subject != "" {
				impData["subject"] = string(imp.Subject)
			}
			if imp.Account != "" {
				impData["account"] = imp.Account
			}
			if imp.Token != "" {
				impData["token"] = imp.Token
			}
			if imp.LocalSubject != "" {
				impData["local_subject"] = imp.LocalSubject
			}
			if imp.Type != jwt.Unknown {
				impData["type"] = imp.Type.String()
			}
			if imp.Share {
				impData["share"] = true
			}
			if imp.AllowTrace {
				impData["allow_trace"] = true
			}

			imports[i] = impData
		}
		data["imports"] = imports
	}

	return &logical.Response{Data: data}, nil
}

func (b *backend) pathAccountImportExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	imp, err := b.AccountImport(ctx, req.Storage, AccountImportIdField(d))
	if err != nil {
		return false, err
	}

	return imp != nil, nil
}

func (b *backend) pathAccountImportList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	after := data.Get("after").(string)
	limit := data.Get("limit").(int)
	if limit <= 0 {
		limit = -1
	}

	entries, err := req.Storage.ListPage(ctx, AccountIdField(data).importPrefix(), after, limit)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathAccountImportDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	txRollback, err := shimtx.StartTxStorageWithShim(ctx, req)
	if err != nil {
		return nil, err
	}
	defer txRollback()

	id := AccountImportIdField(d)

	err = deleteFromStorage(ctx, req.Storage, id.configPath())
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{}

	warnings, err := b.issueAndSaveAccountJWT(ctx, req.Storage, id.accountId())
	if err != nil {
		return nil, fmt.Errorf("failed to encode account jwt: %w", err)
	}

	for _, v := range warnings {
		resp.AddWarning(fmt.Sprintf("while reissuing jwt for account %q: %s", id.acc, v))
	}

	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}

	accountSync, err := b.getAccountSync(ctx, req.Storage, id.operatorId())
	if err != nil {
		b.Logger().Warn("failed to retrieve account sync", "operator", id.op, "account", id.acc, "error", err)
		resp.AddWarning(fmt.Sprintf("unable to sync jwt for account %q: %s", id.acc, err))
	} else if accountSync != nil {
		err := b.syncAccountUpdate(ctx, req.Storage, accountSync, id.accountId())
		if err != nil {
			b.Logger().Warn("failed to sync account", "operator", id.op, "account", id.acc, "error", err)
			resp.AddWarning(fmt.Sprintf("unable to sync jwt for account %q: %s", id.acc, err))
		}
	}

	return resp, nil
}

func (b *backend) listAccountImports(
	ctx context.Context,
	storage logical.Storage,
	id accountId,
) iter.Seq2[*accountImportEntry, error] {
	return func(yield func(*accountImportEntry, error) bool) {
		for p, err := range listPaged(ctx, storage, id.importPrefix(), DefaultPagingSize) {
			if err != nil {
				yield(nil, err)
				return
			}

			rev, err := b.AccountImport(ctx, storage, id.importId(p))
			if err != nil {
				yield(nil, err)
				return
			}
			if rev == nil {
				continue
			}
			if !yield(rev, nil) {
				return
			}
		}
	}
}

func updateImportParams(params map[string]any, imp *jwt.Import) (bool, bool, error) {
	dirty := false
	hasParams := false

	if nameRaw, ok := params["name"]; ok {
		hasParams = true
		name, ok := nameRaw.(string)
		if !ok {
			return false, false, fmt.Errorf("name must be a string, got %T", params["name"])
		}
		dirty = dirty || (name != imp.Name)
		imp.Name = name
	}
	if subjectRaw, ok := params["subject"]; ok {
		hasParams = true
		subject, ok := subjectRaw.(string)
		if !ok {
			return false, false, fmt.Errorf("subject must be a string, got %T", params["account"])
		}
		sub := jwt.Subject(subject)
		dirty = dirty || (sub != imp.Subject)
		imp.Subject = sub
	}

	if accountRaw, ok := params["account"]; ok {
		hasParams = true
		account, ok := accountRaw.(string)
		if !ok {
			return false, false, fmt.Errorf("account must be a string, got %T", params["account"])
		}
		dirty = dirty || (account != imp.Account)
		imp.Account = account
	}

	if tokenRaw, ok := params["token"]; ok {
		hasParams = true
		token, ok := tokenRaw.(string)
		if !ok {
			return false, false, fmt.Errorf("token must be a string, got %T", params["token"])
		}
		dirty = dirty || (token != imp.Token)
		imp.Token = token
	}

	if localSubjectRaw, ok := params["localSubject"]; ok {
		hasParams = true
		localSubject, ok := localSubjectRaw.(string)
		if !ok {
			return false, false, fmt.Errorf("localSubject must be a string, got %T", params["localSubject"])
		}
		sub := jwt.RenamingSubject(localSubject)
		dirty = dirty || (sub != imp.LocalSubject)
		imp.LocalSubject = sub
	}

	if typeRaw, ok := params["type"]; ok {
		hasParams = true
		typ, ok := typeRaw.(string)
		if !ok {
			return false, false, fmt.Errorf("type must be a string, got %T", params["type"])
		}
		var exportType jwt.ExportType
		switch typ {
		case "stream":
			exportType = jwt.Stream
		case "service":
			exportType = jwt.Service
		default:
			return false, false, fmt.Errorf(`type must be either "stream" or "service", got %q`, params["type"])
		}
		dirty = dirty || (exportType != imp.Type)
		imp.Type = exportType
	}

	if shareRaw, ok := params["share"]; ok {
		hasParams = true
		share, ok := shareRaw.(bool)
		if !ok {
			return false, false, fmt.Errorf("share must be a bool, got %T", params["share"])
		}
		imp.Share = share
		dirty = dirty || (share != imp.Share)
	}

	if allowTraceRaw, ok := params["allow_trace"]; ok {
		hasParams = true
		allowTrace, ok := allowTraceRaw.(bool)
		if !ok {
			return false, false, fmt.Errorf("share must be a bool, got %T", params["share"])
		}
		imp.AllowTrace = allowTrace
		dirty = dirty || (allowTrace != imp.AllowTrace)
	}

	return hasParams, dirty, nil
}
