package gittuf

import (
	"github.com/gittuf/gittuf/internal/hooks"
)

// FetchHooksMetadata returns the Hook metadata for the state passed in
func (r *Repository) FetchHooksMetadata(state *hooks.HookState) (*hooks.Metadata, error) {
	return state.GetHooksMetadata()
}

// AddHookFile adds the given file as a hook according to gittuf's spec
func (r *Repository) AddHookFile(filepath, stage, hookName, env string, modules, keyIDs []string) error {
	hookIdentifiers := hooks.HookIdentifiers{
		Filepath:    filepath,
		Stage:       stage,
		Hookname:    hookName,
		Environment: env,
		Modules:     modules,
		KeyIDs:      keyIDs,
	}

	return r.AddHooks(hookIdentifiers)
}
