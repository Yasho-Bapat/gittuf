package init

import (
	"github.com/gittuf/gittuf/internal/cmd/common"
	"github.com/gittuf/gittuf/internal/cmd/policy/persistent"
	"github.com/gittuf/gittuf/internal/policy"
	"github.com/gittuf/gittuf/internal/repository"
	"github.com/spf13/cobra"
)

type options struct {
	p          *persistent.Options
	policyName string
}

func (o *options) Run(cmd *cobra.Command, _ []string) error {
	repo, err := repository.LoadRepository()
	if err != nil {
		return err
	}

	signer, err := common.LoadSigner(repo, o.p.SigningKey)
	if err != nil {
		return err
	}

	// initialize targets for hook
	return repo.InitializeTargets(cmd.Context(), signer, policy.HooksRoleName, true)
}

func New(persistent *persistent.Options) *cobra.Command {
	o := &options{p: persistent}
	cmd := &cobra.Command{
		Use:               "init",
		Short:             "Initialize hooks ref",
		PreRunE:           common.CheckIfSigningViableWithFlag,
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}

	return cmd
}
