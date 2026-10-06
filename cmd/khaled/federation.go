package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/ckapraw"
	"github.com/spf13/cobra"

	"github.com/messier-42/khaled/pkg/plugin"
	"github.com/messier-42/khaled/pkg/plugin/keystorage"
)

// Maintenance opens the daemon's unified store through the plugin factory. Its
// process lock remains authoritative, including for public identity reads.
func newFederationCmd() *cobra.Command {
	var storePath, domainName string
	cmd := &cobra.Command{
		Use: "federation", Short: "Maintain federation keys in the unified key store",
		Long: "Maintain federation identity and keys in the daemon's SQLite key store.\nStop the daemon before running these commands: the store requires an exclusive process lock.",
	}
	cmd.PersistentFlags().StringVar(&storePath, "store", "", "Existing directory containing the daemon's SQLite key store (required).")
	cmd.PersistentFlags().StringVar(&domainName, "domain-name", "default", "Storage domain name.")
	_ = cmd.MarkPersistentFlagRequired("store")
	withDomain := func(cmd *cobra.Command, action func(keystorage.FederationDomain) error) (retErr error) {
		if storePath == "" || domainName == "" {
			return errors.New("--store and --domain-name must not be empty")
		}
		args := plugin.KeyStorageArgs{PluginName: "disk"}
		args.Disk.Path = storePath
		store, err := plugin.NewKeyStorage(cmd.Context(), args)
		if err != nil {
			return fmt.Errorf("open federation store (stop the daemon before maintenance): %w", err)
		}
		defer func() { retErr = errors.Join(retErr, store.Close()) }()
		domain, err := store.DomainByName(cmd.Context(), domainName)
		if err != nil {
			return err
		}
		federation, ok := domain.(keystorage.FederationDomain)
		if !ok {
			return errors.New("key storage domain does not support federation")
		}
		return action(federation)
	}

	var domainID string
	initCmd := &cobra.Command{Use: "init", Short: "Bind a federation domain identity and create its first key", Args: cobra.NoArgs}
	initOptions := federationKeyFlags(initCmd)
	initCmd.Flags().StringVar(&domainID, "domain-id", "", "Stable federation Domain ID (required).")
	_ = initCmd.MarkFlagRequired("domain-id")
	initCmd.RunE = func(cmd *cobra.Command, _ []string) error {
		options, err := initOptions()
		if err != nil {
			return err
		}
		if domainID == "" {
			return errors.New("--domain-id must not be empty")
		}
		return withDomain(cmd, func(d keystorage.FederationDomain) error {
			return d.BindFederation(cmd.Context(), domainID, options)
		})
	}

	identityCmd := &cobra.Command{
		Use: "identity", Short: "Print base64 CKAP FederationIdentity CBOR for peer configuration", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withDomain(cmd, func(d keystorage.FederationDomain) error {
				id, err := d.FederationIdentity(cmd.Context())
				if err != nil {
					return err
				}
				if id == "" {
					return errors.New("federation identity is not initialized; run federation init first")
				}
				identity := ckapraw.FederationIdentity{Kind: ckapraw.KindFederationIdentity, DomainID: id}
				now := time.Now()
				for k, err := range d.ListFederationKeys(cmd.Context()) {
					if err != nil {
						return err
					}
					if k.Advertised(now) {
						identity.Keys = append(identity.Keys, ckapraw.FederationPublicKey{PublicKey: k.PublicKey(), Status: string(k.Status(now))})
					}
				}
				raw, err := key.MarshalCBOR(identity)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), base64.StdEncoding.EncodeToString(raw))
				return err
			})
		},
	}
	listCmd := &cobra.Command{
		Use: "list", Short: "List all retained federation key IDs, statuses, and schedules", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withDomain(cmd, func(d keystorage.FederationDomain) error {
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
				if _, err := fmt.Fprintln(w, "FKID\tSTATUS\tADVERTISED\tCREATED\tACTIVATE\tRETIRE\tUNADVERTISE"); err != nil {
					return err
				}
				now := time.Now()
				for k, err := range d.ListFederationKeys(cmd.Context()) {
					if err != nil {
						return err
					}
					if _, err := fmt.Fprintf(w, "%x\t%s\t%t\t%s\t%s\t%s\t%s\n", k.ID(), k.Status(now), k.Advertised(now), federationTime(k.CreationTime()), federationTime(k.ActivationTime()), federationTime(k.RetirementTime()), federationTime(k.UnadvertiseTime())); err != nil {
						return err
					}
				}
				return w.Flush()
			})
		},
	}

	var fkid, activate, retire, unadvertise string
	rotateCmd := &cobra.Command{Use: "rotate", Short: "Create a successor and schedule an explicit predecessor's retirement", Args: cobra.NoArgs}
	rotateOptions := federationKeyFlags(rotateCmd)
	rotateCmd.Flags().StringVar(&fkid, "fkid", "", "Predecessor FKID in hexadecimal (required).")
	rotateCmd.Flags().StringVar(&activate, "activate", "", "Successor activation time in RFC3339 (default: now).")
	rotateCmd.Flags().StringVar(&retire, "retire", "", "Predecessor retirement time in RFC3339 (default: now).")
	rotateCmd.Flags().StringVar(&unadvertise, "unadvertise", "", "Stop advertising the predecessor at this RFC3339 time (default: never).")
	_ = rotateCmd.MarkFlagRequired("fkid")
	rotateCmd.RunE = func(cmd *cobra.Command, _ []string) error {
		options, err := rotateOptions()
		if err != nil {
			return err
		}
		id, err := hex.DecodeString(fkid)
		if err != nil || len(id) == 0 {
			return errors.New("--fkid must be a non-empty hexadecimal key ID")
		}
		rollover := keystorage.FederationRollover{Options: options}
		for _, field := range []struct {
			name, value string
			target      *time.Time
		}{{"activate", activate, &rollover.Activate}, {"retire", retire, &rollover.Retire}, {"unadvertise", unadvertise, &rollover.Unadvertise}} {
			if field.value == "" {
				continue
			}
			*field.target, err = time.Parse(time.RFC3339, field.value)
			if err != nil {
				return fmt.Errorf("--%s must be RFC3339: %w", field.name, err)
			}
			if field.target.IsZero() {
				return fmt.Errorf("--%s must not be the zero timestamp; omit the flag to use its default", field.name)
			}
		}
		// Zero defaults are resolved together inside the storage transaction.
		return withDomain(cmd, func(d keystorage.FederationDomain) error {
			old, err := d.FederationKeyByID(cmd.Context(), id)
			if err != nil {
				return err
			}
			successor, err := d.RotateFederationKey(cmd.Context(), old, rollover)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%x\n", successor.ID())
			return err
		})
	}
	cmd.AddCommand(initCmd, identityCmd, listCmd, rotateCmd)
	return cmd
}

func federationKeyFlags(cmd *cobra.Command) func() (keystorage.FederationKeyOptions, error) {
	var curve, algorithm string
	cmd.Flags().StringVar(&curve, "curve", "P-256", "Federation key curve: P-256, P-384, or P-521.")
	cmd.Flags().StringVar(&algorithm, "algorithm", "ECDH-ES+A256KW", "Federation key algorithm: ECDH-ES+A128KW, ECDH-ES+A192KW, or ECDH-ES+A256KW.")
	return func() (keystorage.FederationKeyOptions, error) {
		options := keystorage.FederationKeyOptions{}
		switch curve {
		case "P-256":
			options.Curve = iana.EllipticCurveP_256
		case "P-384":
			options.Curve = iana.EllipticCurveP_384
		case "P-521":
			options.Curve = iana.EllipticCurveP_521
		default:
			return options, fmt.Errorf("unsupported federation curve %q: use P-256, P-384, or P-521", curve)
		}
		switch algorithm {
		case "ECDH-ES+A128KW":
			options.Algorithm = iana.AlgorithmECDH_ES_A128KW
		case "ECDH-ES+A192KW":
			options.Algorithm = iana.AlgorithmECDH_ES_A192KW
		case "ECDH-ES+A256KW":
			options.Algorithm = iana.AlgorithmECDH_ES_A256KW
		default:
			return options, fmt.Errorf("unsupported federation algorithm %q", algorithm)
		}
		return options, nil
	}
}

func federationTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339Nano)
}
