package natsbackend

import (
	"context"
	"fmt"
	"iter"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/shimtx"
	"github.com/nats-io/jwt/v2"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
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
		acc:  d.Get("account").(string),
		name: d.Get("name").(string),
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
			Pattern: accountImportsPathPrefix + operatorRegex + "/" + accountRegex + "/" + nameRegex + "$",
			Fields: map[string]*framework.FieldSchema{
				"operator": operatorField,
				"account":  accountField,
				"name": {
					Type:        framework.TypeString,
					Description: `The name given to this collection of imports.`,
					Required:    true,
				},
				"imports": {
					Type:        framework.TypeSlice,
					Description: "A list of import definitions to define on the account. At least one import must be specified.",
					Required:    true,
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

		jwtDirty = jwtDirty || (len(importsRaw) != len(accImport.Imports))

		imports := make(jwt.Imports, len(importsRaw))
		prevImports := accImport.Imports
		if prevImports == nil {
			prevImports = imports
		}
		for i, v := range importsRaw {
			if importRaw, ok := v.(map[string]any); ok {
				imp := jwt.Import{}
				imports[i] = &imp

				var prev *jwt.Import
				if i < prevImports.Len() {
					prev = prevImports[i]
				} else {
					jwtDirty = true
				}

				if nameRaw, ok := importRaw["name"]; ok {
					name, ok := nameRaw.(string)
					if !ok {
						return logical.ErrorResponse("import[%d].name must be a string, got %T", i, importRaw["name"]), nil
					}
					imp.Name = name
					jwtDirty = jwtDirty || (imp.Name != prev.Name)
				}
				if subjectRaw, ok := importRaw["subject"]; ok {
					subject, ok := subjectRaw.(string)
					if !ok {
						return logical.ErrorResponse("import[%d].subject must be a string, got %T", i, importRaw["account"]), nil
					}
					imp.Subject = jwt.Subject(subject)
					jwtDirty = jwtDirty || (imp.Subject != prev.Subject)
				}

				if accountRaw, ok := importRaw["account"]; ok {
					account, ok := accountRaw.(string)
					if !ok {
						return logical.ErrorResponse("import[%d].account must be a string, got %T", i, importRaw["account"]), nil
					}
					imp.Account = account
					jwtDirty = jwtDirty || (imp.Account != prev.Account)
				}

				if tokenRaw, ok := importRaw["token"]; ok {
					token, ok := tokenRaw.(string)
					if !ok {
						return logical.ErrorResponse("import[%d].token must be a string, got %T", i, importRaw["token"]), nil
					}
					imp.Token = token
					jwtDirty = jwtDirty || (imp.Token != prev.Token)
				}

				if localSubjectRaw, ok := importRaw["localSubject"]; ok {
					localSubject, ok := localSubjectRaw.(string)
					if !ok {
						return logical.ErrorResponse("import[%d].localSubject must be a string, got %T", i, importRaw["localSubject"]), nil
					}
					imp.LocalSubject = jwt.RenamingSubject(localSubject)
					jwtDirty = jwtDirty || (imp.LocalSubject != prev.LocalSubject)
				}

				if typeRaw, ok := importRaw["type"]; ok {
					typ, ok := typeRaw.(string)
					if !ok {
						return logical.ErrorResponse("import[%d].type must be an int, got %T", i, importRaw["type"]), nil
					}
					switch typ {
					case "stream":
						imp.Type = jwt.Stream
					case "service":
						imp.Type = jwt.Service
					default:
						return logical.ErrorResponse(`import[%d].type must be either "stream" or "service", got %q`, i, importRaw["type"]), nil
					}
					jwtDirty = jwtDirty || (imp.Type != prev.Type)
				}

				if shareRaw, ok := importRaw["share"]; ok {
					share, ok := shareRaw.(bool)
					if !ok {
						return logical.ErrorResponse("import[%d].share must be a bool, got %T", i, importRaw["share"]), nil
					}
					imp.Share = share
					jwtDirty = jwtDirty || (imp.Share != prev.Share)
				}
			} else {
				return logical.ErrorResponse("import must be a map, got %T", v), nil
			}
		}

		accImport.Imports = imports
	}

	if len(accImport.Imports) == 0 {
		return logical.ErrorResponse("must define at least one import"), nil
	}

	err = storeInStorage(ctx, req.Storage, accImport.configPath(), accImport)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{}

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
