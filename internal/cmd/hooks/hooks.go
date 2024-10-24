package hooks

import (
	i "github.com/gittuf/gittuf/internal/cmd/hooks/init"
	"github.com/gittuf/gittuf/internal/cmd/policy/persistent"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	o := &persistent.Options{}
	cmd := &cobra.Command{
		Use:               "hooks",
		Short:             "Tools to manage git hooks",
		DisableAutoGenTag: true,
	}
	o.AddPersistentFlags(cmd)

	cmd.AddCommand(i.New(o))

	return cmd
}
