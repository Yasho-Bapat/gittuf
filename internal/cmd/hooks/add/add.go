package add

import (
	"context"
	"errors"
	"fmt"
	"github.com/gittuf/gittuf/experimental/gittuf"
	"github.com/gittuf/gittuf/internal/cmd/trust/persistent"
	"github.com/gittuf/gittuf/internal/gitinterface"
	"github.com/gittuf/gittuf/internal/hooks"
	"github.com/gittuf/gittuf/internal/rsl"
	"github.com/spf13/cobra"
)

// todo: this function must take 2 arguments: path/to/hooks/file and stage
// the file specified by the file must be copied properly and securely into directory
// the stage specified by the data in the -s flag must be used for generating the metadata
// the metadata can be as simple as
// stage: path/to/hook
// the metadata file will have to be updated everytime gittuf hooks add is called
// the directory structure will be:
// hooks/
//		hooksMetadata.json
//		hook1.hook
//		hook2.hook

// QUESTIONS: where will we be copying the scripts to?

type options struct {
	p        *persistent.Options
	filepath string
	stage    string
	hookname string
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(
		&o.filepath,
		"file",
		"",
		"filepath of the script to be run as a hook",
	)
	cmd.MarkFlagRequired("file")

	cmd.Flags().StringVar(
		&o.stage,
		"stage",
		"",
		"stage at which the hook must be run",
	)
	cmd.MarkFlagRequired("stage")

	cmd.Flags().StringVar(
		&o.hookname,
		"hookname",
		"default",
		"Name of the hook",
	)
}

func (o *options) Run(cmd *cobra.Command, _ []string) error {
	repo, err := gittuf.LoadRepository()
	if err != nil {
		return err
	}

	// initialize policy
	// add rule for protecting refs/gittuf/hooks

	r := repo.GetGitRepository()
	hooksTip, err := r.GetReference(hooks.HooksRef)
	if err != nil {
		if !errors.Is(err, gitinterface.ErrReferenceNotFound) {
			return fmt.Errorf("failed to get policy reference %s: %w", hooksTip, err)
		}
	}

	state, err := hooks.LoadCurrentState(context.Background(), r, hooks.HooksRef)
	if err != nil {
		if !errors.Is(err, rsl.ErrRSLEntryNotFound) {
			return fmt.Errorf("failed to load hooks: %w", err)
		}
	}

	return state.Add(r, o.filepath, o.stage, o.hookname)
}

func New() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:               "add",
		Short:             "add a script to be run as a hook and mention when to run it.",
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}
	o.AddFlags(cmd)

	return cmd
}
