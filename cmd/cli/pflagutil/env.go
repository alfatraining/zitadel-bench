package pflagutil

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/pflag"
)

// PopulateFromEnv populates a [pflag.FlagSet] with values from the environment.
func PopulateFromEnv(flags *pflag.FlagSet) error {
	var errs []error
	flags.VisitAll(func(flag *pflag.Flag) {
		v, ok := os.LookupEnv(toEnvName(flag.Name))
		if !ok {
			return
		}
		if err := flag.Value.Set(v); err != nil {
			errs = append(errs, err)
		}
	})
	return errors.Join(errs...)
}

// PrintEnvUsage prints the [pflag.FlagSet] usage for environment configurations.
func PrintEnvUsage(flags *pflag.FlagSet) {
	tw := tabwriter.NewWriter(os.Stdout, 10, 8, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprint(tw, "Environment configuration:\n\n")
	fmt.Fprintf(tw, " %s\t%s\t%s\t%s\n", "Key", "Type", "Default", "Description")
	fmt.Fprint(tw, " ---\t----\t-------\t-----------\n")
	flags.VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" || flag.Name == "help-env" {
			return
		}
		fmt.Fprintf(tw, " %s\t%s\t%s\t%s\n", toEnvName(flag.Name), flag.Value.Type(), flag.DefValue, flag.Usage)
	})
}

var replacer = strings.NewReplacer("-", "_")

func toEnvName(in string) string {
	return strings.ToUpper(replacer.Replace(in))
}
