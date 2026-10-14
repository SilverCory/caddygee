package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"caddygee/internal/apigee"
	"caddygee/internal/transpiler"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "caddygee",
		Short: "Apigee to Caddy migration tool",
	}
	root.AddCommand(transpileCmd())
	root.AddCommand(validateCmd())
	root.AddCommand(mergeCmd())
	return root
}

func transpileCmd() *cobra.Command {
	var (
		input    string
		output   string
		format   string
		listen   string
		fragment bool
		cloudRun bool
	)
	cmd := &cobra.Command{
		Use:   "transpile",
		Short: "Convert an Apigee API proxy bundle to a Caddy configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			bundle, err := apigee.ParseBundle(input)
			if err != nil {
				return fmt.Errorf("parsing bundle: %w", err)
			}
			out, err := transpiler.Emit(bundle, transpiler.Options{
				Format:        format,
				ListenAddress: listen,
				Fragment:      fragment,
				CloudRun:      cloudRun,
			})
			if err != nil {
				return fmt.Errorf("transpiling: %w", err)
			}
			if output == "" || output == "-" {
				fmt.Print(out)
				return nil
			}
			return os.WriteFile(output, []byte(out), 0o644)
		},
	}
	cmd.Flags().StringVarP(&input, "input", "i", "", "Path to apiproxy/ directory (required)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().StringVarP(&format, "format", "f", "caddyfile", "Output format: caddyfile or json")
	cmd.Flags().StringVarP(&listen, "listen", "l", ":443", "Caddy listen address")
	cmd.Flags().BoolVar(&fragment, "fragment", false, "Emit bare route content only (no server block), for use with the deploy endpoint")
	cmd.Flags().BoolVar(&cloudRun, "cloud-run", false, "Prepend Cloud Run global options (admin, auto_https off, trusted_proxies, logging, /health)")
	_ = cmd.MarkFlagRequired("input")
	return cmd
}

func mergeCmd() *cobra.Command {
	var (
		input    string
		output   string
		listen   string
		cloudRun bool
	)
	cmd := &cobra.Command{
		Use:   "merge",
		Short: "Merge Caddyfile fragments from a directory into a complete Caddyfile",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := transpiler.MergeFragments(input, transpiler.Options{
				ListenAddress: listen,
				CloudRun:      cloudRun,
			})
			if err != nil {
				return fmt.Errorf("merging fragments: %w", err)
			}
			if output == "" || output == "-" {
				fmt.Print(out)
				return nil
			}
			return os.WriteFile(output, []byte(out), 0o644)
		},
	}
	cmd.Flags().StringVarP(&input, "input", "i", "", "Directory containing *.caddyfile fragments (required)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().StringVarP(&listen, "listen", "l", ":8080", "Caddy listen address")
	cmd.Flags().BoolVar(&cloudRun, "cloud-run", false, "Prepend Cloud Run global options")
	_ = cmd.MarkFlagRequired("input")
	return cmd
}

func validateCmd() *cobra.Command {
	var input string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Parse an Apigee bundle and print a summary without emitting config",
		RunE: func(cmd *cobra.Command, args []string) error {
			bundle, err := apigee.ParseBundle(input)
			if err != nil {
				return fmt.Errorf("parsing bundle: %w", err)
			}
			fmt.Printf("Proxy endpoints:  %d\n", len(bundle.ProxyEndpoints))
			fmt.Printf("Target endpoints: %d\n", len(bundle.TargetEndpoints))
			fmt.Printf("Policies:         %d\n", len(bundle.Policies))
			for _, ep := range bundle.ProxyEndpoints {
				fmt.Printf("\nProxy endpoint %q  base path: %s\n", ep.Name, ep.HTTPProxyConnection.BasePath)
				fmt.Printf("  PreFlow request steps:  %d\n", len(ep.PreFlow.Request.Steps))
				fmt.Printf("  PostFlow request steps: %d\n", len(ep.PostFlow.Request.Steps))
				fmt.Printf("  Named flows: %d\n", len(ep.Flows))
				for _, f := range ep.Flows {
					fmt.Printf("    - %s  condition: %q  request steps: %d\n",
						f.Name, f.Condition, len(f.Request.Steps))
				}
			}
			for _, te := range bundle.TargetEndpoints {
				fmt.Printf("\nTarget endpoint %q  URL: %s\n", te.Name, te.HTTPTargetConnection.URL)
			}
			for name, pol := range bundle.Policies {
				fmt.Printf("Policy %q  type: %s\n", name, pol.Type)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&input, "input", "i", "", "Path to apiproxy/ directory (required)")
	_ = cmd.MarkFlagRequired("input")
	return cmd
}
