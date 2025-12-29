package main

import (
	"log"
	"os"

	nats "github.com/bonesofgiants/openbao-plugin-secrets-nats"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: nats.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		log.Default().Printf("plugin shutting down: %v", err)
		os.Exit(1)
	}
}
