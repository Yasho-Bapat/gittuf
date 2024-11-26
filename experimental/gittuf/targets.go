// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gittuf

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/gittuf/gittuf/internal/gitinterface"
	"github.com/gittuf/gittuf/internal/hooks"
	"github.com/gittuf/gittuf/internal/rsl"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/gittuf/gittuf/internal/policy"
	"github.com/gittuf/gittuf/internal/signerverifier/dsse"
	sslibdsse "github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/dsse"
	"github.com/gittuf/gittuf/internal/tuf"
)

var ErrInvalidPolicyName = errors.New("invalid rule or policy file name, cannot be 'root'")

// InitializeTargets is the interface for the user to create the specified
// policy file.
func (r *Repository) InitializeTargets(ctx context.Context, signer sslibdsse.SignerVerifier, targetsRoleName string, signCommit bool) error {
	if targetsRoleName == policy.RootRoleName {
		return ErrInvalidPolicyName
	}

	keyID, err := signer.KeyID()
	if err != nil {
		return err
	}

	slog.Debug("Loading current policy...")
	state, err := policy.LoadCurrentState(ctx, r.r, policy.PolicyStagingRef)
	if err != nil {
		return err
	}
	if state.HasTargetsRole(targetsRoleName) {
		return ErrCannotReinitialize
	}

	// TODO: verify is role can be signed using the presented key. This requires
	// the user to pass in the delegating role as well as we do not want to
	// assume which role is the delegating role (diamond delegations are legal).
	// See: https://github.com/gittuf/gittuf/issues/246.

	slog.Debug("Creating initial rule file...")
	targetsMetadata := policy.InitializeTargetsMetadata()

	env, err := dsse.CreateEnvelope(targetsMetadata)
	if err != nil {
		return err
	}

	slog.Debug(fmt.Sprintf("Signing initial rule file using '%s'...", keyID))
	env, err = dsse.SignEnvelope(ctx, env, signer)
	if err != nil {
		return err
	}

	if targetsRoleName == policy.TargetsRoleName {
		state.TargetsEnvelope = env
	} else {
		if state.DelegationEnvelopes == nil {
			state.DelegationEnvelopes = map[string]*sslibdsse.Envelope{}
		}
		state.DelegationEnvelopes[targetsRoleName] = env
	}

	commitMessage := fmt.Sprintf("Initialize policy '%s'", targetsRoleName)

	slog.Debug("Committing policy...")
	return state.Commit(r.r, commitMessage, signCommit)
}

// AddDelegation is the interface for the user to add a new rule to gittuf
// policy.
func (r *Repository) AddDelegation(ctx context.Context, signer sslibdsse.SignerVerifier, targetsRoleName string, ruleName string, authorizedKeys []tuf.Principal, rulePatterns []string, threshold int, signCommit bool) error {
	if ruleName == policy.RootRoleName {
		return ErrInvalidPolicyName
	}

	keyID, err := signer.KeyID()
	if err != nil {
		return err
	}

	slog.Debug("Loading current policy...")
	state, err := policy.LoadCurrentState(ctx, r.r, policy.PolicyStagingRef)
	if err != nil {
		return err
	}

	slog.Debug("Checking if rule with same name exists...")
	if state.HasRuleName(ruleName) {
		return tuf.ErrDuplicatedRuleName
	}

	slog.Debug("Loading current rule file...")
	if !state.HasTargetsRole(targetsRoleName) {
		return policy.ErrMetadataNotFound
	}

	// TODO: verify is role can be signed using the presented key. This requires
	// the user to pass in the delegating role as well as we do not want to
	// assume which role is the delegating role (diamond delegations are legal).
	// See: https://github.com/gittuf/gittuf/issues/246.

	targetsMetadata, err := state.GetTargetsMetadata(targetsRoleName)
	if err != nil {
		return err
	}

	slog.Debug("Adding rule to rule file...")
	if err := targetsMetadata.AddRule(ruleName, authorizedKeys, rulePatterns, threshold); err != nil {
		return err
	}

	env, err := dsse.CreateEnvelope(targetsMetadata)
	if err != nil {
		return err
	}

	slog.Debug(fmt.Sprintf("Signing updated rule file using '%s'...", keyID))
	env, err = dsse.SignEnvelope(ctx, env, signer)
	if err != nil {
		return err
	}

	if targetsRoleName == policy.TargetsRoleName {
		state.TargetsEnvelope = env
	} else {
		state.DelegationEnvelopes[targetsRoleName] = env
	}

	commitMessage := fmt.Sprintf("Add rule '%s' to policy '%s'", ruleName, targetsRoleName)

	slog.Debug("Committing policy...")
	return state.Commit(r.r, commitMessage, signCommit)
}

// UpdateDelegation is the interface for the user to update a rule to gittuf
// policy.
func (r *Repository) UpdateDelegation(ctx context.Context, signer sslibdsse.SignerVerifier, targetsRoleName string, ruleName string, authorizedKeys []tuf.Principal, rulePatterns []string, threshold int, signCommit bool) error {
	if ruleName == policy.RootRoleName {
		return ErrInvalidPolicyName
	}

	keyID, err := signer.KeyID()
	if err != nil {
		return err
	}

	slog.Debug("Loading current policy...")
	state, err := policy.LoadCurrentState(ctx, r.r, policy.PolicyStagingRef)
	if err != nil {
		return err
	}

	slog.Debug("Loading current rule file...")
	if !state.HasTargetsRole(targetsRoleName) {
		return policy.ErrMetadataNotFound
	}

	// TODO: verify is role can be signed using the presented key. This requires
	// the user to pass in the delegating role as well as we do not want to
	// assume which role is the delegating role (diamond delegations are legal).
	// See: https://github.com/gittuf/gittuf/issues/246.

	targetsMetadata, err := state.GetTargetsMetadata(targetsRoleName)
	if err != nil {
		return err
	}

	slog.Debug("Updating rule in rule file...")
	if err := targetsMetadata.UpdateRule(ruleName, authorizedKeys, rulePatterns, threshold); err != nil {
		return err
	}

	env, err := dsse.CreateEnvelope(targetsMetadata)
	if err != nil {
		return err
	}

	slog.Debug(fmt.Sprintf("Signing updated rule file using '%s'...", keyID))
	env, err = dsse.SignEnvelope(ctx, env, signer)
	if err != nil {
		return err
	}

	if targetsRoleName == policy.TargetsRoleName {
		state.TargetsEnvelope = env
	} else {
		state.DelegationEnvelopes[targetsRoleName] = env
	}

	commitMessage := fmt.Sprintf("Update rule '%s' in policy '%s'", ruleName, targetsRoleName)

	slog.Debug("Committing policy...")
	return state.Commit(r.r, commitMessage, signCommit)
}

// ReorderDelegations is the interface for the user to reorder rules in gittuf
// policy.
func (r *Repository) ReorderDelegations(ctx context.Context, signer sslibdsse.SignerVerifier, targetsRoleName string, ruleNames []string, signCommit bool) error {
	keyID, err := signer.KeyID()
	if err != nil {
		return nil
	}

	slog.Debug("Loading current policy...")
	state, err := policy.LoadCurrentState(ctx, r.r, policy.PolicyStagingRef)
	if err != nil {
		return err
	}

	slog.Debug("Loading current rule file...")
	if !state.HasTargetsRole(targetsRoleName) {
		return policy.ErrMetadataNotFound
	}

	targetsMetadata, err := state.GetTargetsMetadata(targetsRoleName)
	if err != nil {
		return err
	}

	slog.Debug("Reordering rules in rule file...")
	if err := targetsMetadata.ReorderRules(ruleNames); err != nil {
		return err
	}

	env, err := dsse.CreateEnvelope(targetsMetadata)
	if err != nil {
		return err
	}

	slog.Debug(fmt.Sprintf("Signing updated rule file using '%s'...", keyID))
	env, err = dsse.SignEnvelope(ctx, env, signer)
	if err != nil {
		return err
	}

	if targetsRoleName == policy.TargetsRoleName {
		state.TargetsEnvelope = env
	} else {
		state.DelegationEnvelopes[targetsRoleName] = env
	}

	commitMessage := fmt.Sprintf("Reorder rules in policy '%s'", targetsRoleName)

	slog.Debug("Committing policy...")
	return state.Commit(r.r, commitMessage, signCommit)
}

// RemoveDelegation is the interface for a user to remove a rule from gittuf
// policy.
func (r *Repository) RemoveDelegation(ctx context.Context, signer sslibdsse.SignerVerifier, targetsRoleName string, ruleName string, signCommit bool) error {
	keyID, err := signer.KeyID()
	if err != nil {
		return err
	}

	slog.Debug("Loading current policy...")
	state, err := policy.LoadCurrentState(ctx, r.r, policy.PolicyStagingRef)
	if err != nil {
		return err
	}

	slog.Debug("Loading current rule file...")
	if !state.HasTargetsRole(targetsRoleName) {
		return policy.ErrMetadataNotFound
	}

	// TODO: verify is role can be signed using the presented key. This requires
	// the user to pass in the delegating role as well as we do not want to
	// assume which role is the delegating role (diamond delegations are legal).
	// See: https://github.com/gittuf/gittuf/issues/246.

	targetsMetadata, err := state.GetTargetsMetadata(targetsRoleName)
	if err != nil {
		return err
	}

	slog.Debug("Removing rule from rule file...")
	if err := targetsMetadata.RemoveRule(ruleName); err != nil {
		return err
	}

	env, err := dsse.CreateEnvelope(targetsMetadata)
	if err != nil {
		return err
	}

	slog.Debug(fmt.Sprintf("Signing updated rule file using '%s'...", keyID))
	env, err = dsse.SignEnvelope(ctx, env, signer)
	if err != nil {
		return err
	}

	if targetsRoleName == policy.TargetsRoleName {
		state.TargetsEnvelope = env
	} else {
		state.DelegationEnvelopes[targetsRoleName] = env
	}

	commitMessage := fmt.Sprintf("Remove rule '%s' from policy '%s'", ruleName, targetsRoleName)

	slog.Debug("Committing policy...")
	return state.Commit(r.r, commitMessage, signCommit)
}

// AddKeyToTargets is the interface for a user to add a trusted key to the
// gittuf policy.
func (r *Repository) AddKeyToTargets(ctx context.Context, signer sslibdsse.SignerVerifier, targetsRoleName string, authorizedKeys []tuf.Principal, signCommit bool) error {
	keyID, err := signer.KeyID()
	if err != nil {
		return err
	}

	slog.Debug("Loading current policy...")
	state, err := policy.LoadCurrentState(ctx, r.r, policy.PolicyStagingRef)
	if err != nil {
		return err
	}
	if !state.HasTargetsRole(targetsRoleName) {
		return policy.ErrMetadataNotFound
	}

	// TODO: verify is role can be signed using the presented key. This requires
	// the user to pass in the delegating role as well as we do not want to
	// assume which role is the delegating role (diamond delegations are legal).
	// See: https://github.com/gittuf/gittuf/issues/246.

	keyIDs := ""
	for _, key := range authorizedKeys {
		keyIDs += fmt.Sprintf("\n%s", key.ID())
	}

	slog.Debug("Loading current rule file...")
	targetsMetadata, err := state.GetTargetsMetadata(targetsRoleName)
	if err != nil {
		return err
	}

	slog.Debug("Adding key to rule file...")
	for _, authorizedKey := range authorizedKeys {
		if err := targetsMetadata.AddPrincipal(authorizedKey); err != nil {
			return err
		}
	}

	env, err := dsse.CreateEnvelope(targetsMetadata)
	if err != nil {
		return err
	}

	slog.Debug(fmt.Sprintf("Signing updated rule file using '%s'...", keyID))
	env, err = dsse.SignEnvelope(ctx, env, signer)
	if err != nil {
		return err
	}

	if targetsRoleName == policy.TargetsRoleName {
		state.TargetsEnvelope = env
	} else {
		state.DelegationEnvelopes[targetsRoleName] = env
	}

	commitMessage := fmt.Sprintf("Add keys to policy '%s'\n%s", targetsRoleName, keyIDs)

	slog.Debug("Committing policy...")
	return state.Commit(r.r, commitMessage, signCommit)
}

// SignTargets adds a signature to specified Targets role's envelope. Note that
// the metadata itself is not modified, so its version remains the same.
func (r *Repository) SignTargets(ctx context.Context, signer sslibdsse.SignerVerifier, targetsRoleName string, signCommit bool) error {
	keyID, err := signer.KeyID()
	if err != nil {
		return err
	}

	slog.Debug("Loading current policy...")
	state, err := policy.LoadCurrentState(ctx, r.r, policy.PolicyStagingRef)
	if err != nil {
		return err
	}
	if !state.HasTargetsRole(targetsRoleName) {
		return policy.ErrMetadataNotFound
	}

	var env *sslibdsse.Envelope
	if targetsRoleName == policy.TargetsRoleName {
		env = state.TargetsEnvelope
	} else {
		env = state.DelegationEnvelopes[targetsRoleName]
	}

	slog.Debug(fmt.Sprintf("Signing rule file using '%s'...", keyID))
	env, err = dsse.SignEnvelope(ctx, env, signer)
	if err != nil {
		return err
	}

	if targetsRoleName == policy.TargetsRoleName {
		state.TargetsEnvelope = env
	} else {
		state.DelegationEnvelopes[targetsRoleName] = env
	}

	commitMessage := fmt.Sprintf("Add signature from key '%s' to policy '%s'", keyID, targetsRoleName)

	slog.Debug("Committing policy...")
	return state.Commit(r.r, commitMessage, signCommit)
}

// InitializeHooks initializes the hooks ref, creates targets metadata associated with hooks and creates
// empty hooks metadata, and commits this to the hooks ref (refs/gittuf/hooks)
func (r *Repository) InitializeHooks(ctx context.Context, signer sslibdsse.Signer) error {
	// get current context
	repo := r.GetGitRepository()
	stateChecker, err := hooks.LoadCurrentState(repo)
	if stateChecker != nil {
		return fmt.Errorf("hooks ref already initialized, cannot initialize again")
	}

	// create and start populating state
	state := &hooks.HookState{Repository: repo}

	slog.Debug("Creating initial rule file...")
	targetsMetadata := policy.InitializeTargetsMetadata()

	keyID, err := signer.KeyID()
	if err != nil {
		return err
	}

	fmt.Println("KeyID: ", keyID) // temporary , remove later

	// create DSSE envelope for targets metadata
	env, err := dsse.CreateEnvelope(targetsMetadata)
	if err != nil {
		return err
	}

	slog.Debug(fmt.Sprintf("Signing targets file using '%s'...", keyID))
	env, err = dsse.SignEnvelope(ctx, env, signer)
	if err != nil {
		return err
	}
	state.TargetsEnvelope = env

	slog.Debug("Creating initial empty hooks metadata file...")
	hooksMetadata := hooks.InitializeHooksMetadata()

	env, err = dsse.CreateEnvelope(hooksMetadata)
	if err != nil {
		return err
	}

	slog.Debug(fmt.Sprintf("Signing hooks file using '%s'...", keyID))
	env, err = dsse.SignEnvelope(ctx, env, signer)
	if err != nil {
		return err
	}
	state.HooksEnvelope = env

	return state.Commit(repo, hooks.DefaultCommitMessage, nil, true)
}

// AddHooks defines the workflow for adding a file to be executed as a hook.
// It commits writes the file, populates all fields in the hooks metadata
// associated with this file and commits it to the current ref.
func (r *Repository) AddHooks(o hooks.HookIdentifiers) error {
	// assigning all fields from o
	filePath := o.Filepath
	stage := o.Stage
	hookName := o.Hookname
	execenv := o.Environment
	modules := o.Modules
	keyIDs := o.KeyIDs

	// load repository for the current session
	repo := r.GetGitRepository()
	hooksTip, err := repo.GetReference(hooks.HooksRef)
	if err != nil {
		if !errors.Is(err, gitinterface.ErrReferenceNotFound) {
			return fmt.Errorf("failed to get policy reference %s: %w", hooksTip, err)
		}
	}

	// load current state for the repository
	state, err := hooks.LoadCurrentState(repo)
	if err != nil {
		if !errors.Is(err, rsl.ErrRSLEntryNotFound) {
			return fmt.Errorf("failed to load hooks: %w", err)
		}
	}
	slog.Debug("Loaded current state")

	if hookName == "" {
		hookName = filepath.Base(filePath)
	}

	hookFile, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer hookFile.Close() // nolint:errcheck

	hookFileContents, err := io.ReadAll(hookFile)
	if err != nil {
		return err
	}

	sha256Hash := sha256.New()
	sha256Hash.Write(hookFileContents)
	sha256HashSum := sha256Hash.Sum(nil)

	currentHooksMetadata, err := state.GetHooksMetadata()
	if err != nil {
		return err
	}
	blobID, err := repo.WriteBlob(hookFileContents)
	if err != nil {
		return err
	}

	// the following line should probably be changed to just passing in the o object later.
	if err := currentHooksMetadata.GenerateHooksMetadataFor(hookName, stage, execenv, blobID, sha256HashSum, modules, keyIDs); err != nil {
		return err
	}

	env, err := dsse.CreateEnvelope(currentHooksMetadata)
	if err != nil {
		return err
	}

	// assign HooksEnvelope field with env value
	state.HooksEnvelope = env

	hookCommitMap := map[string]gitinterface.Hash{hookName: blobID}

	commitMessage := "Add " + hookName
	return state.Commit(repo, commitMessage, hookCommitMap, true)
}

// ApplyHooks commits all the hook files that were introduced using AddHooks to
// the current tree, updates the hooks metadata with changes and writes the
// hash of the hooks metadata to the targets metadata.
func (r *Repository) ApplyHooks(ctx context.Context, signer sslibdsse.Signer) error {
	// load git repository for current session
	repo := r.GetGitRepository()
	hooksTip, err := repo.GetReference(hooks.HooksRef)
	if err != nil {
		if !errors.Is(err, gitinterface.ErrReferenceNotFound) {
			return fmt.Errorf("failed to get policy reference %s: %w", hooksTip, err)
		}
	}

	// load latest state for the current repository
	state, err := hooks.LoadCurrentState(repo)

	// get blobIDs from rsl.GetLatestReferenceEntry
	if err != nil {
		if !errors.Is(err, rsl.ErrRSLEntryNotFound) {
			return fmt.Errorf("failed to load hooks: %w", err)
		}
	}
	slog.Debug("Loaded current state")

	hooksMetadata, err := state.GetHooksMetadata()
	if err != nil {
		return err
	}

	// populating the final tree with all hooks to be committed as part of the latest update
	// => getting the file contents from the blob ID, writing the file and updating
	// hooks metadata with the new blob ID.
	hooksApplyMap := make(map[string]gitinterface.Hash)
	for filename, hookInfo := range hooksMetadata.HooksInfo {
		blobID, err := gitinterface.NewHash(hookInfo.BlobID)
		if err != nil {
			return err
		}

		hookFileContents, err := repo.ReadBlob(blobID)
		if err != nil {
			return err
		}

		newBlobID, err := repo.WriteBlob(hookFileContents)
		if err != nil {
			return err
		}

		hooksApplyMap[filename] = newBlobID
		hookInfo.BlobID = newBlobID.String()
		err = hooksMetadata.UpdateHooksMetadata(filename, hookInfo)
		if err != nil {
			return err
		}
	}

	// load targets metadata
	targetsMetadata, err := state.GetTargetsMetadata(hooks.TargetsRoleName)
	if err != nil {
		return err
	}

	h := state.HooksEnvelope
	payloadBytes, err := h.DecodeB64Payload()
	if err != nil {
		return err
	}

	sha256Hash := sha256.New()
	sha256Hash.Write(payloadBytes)
	sha256HashSum := sha256Hash.Sum(nil)

	targetsMetadata.SetHooksField(sha256HashSum)

	env, err := dsse.CreateEnvelope(targetsMetadata)
	if err != nil {
		return err
	}

	// sign new targets data
	env, err = dsse.SignEnvelope(ctx, env, signer)
	if err != nil {
		return err
	}

	state.TargetsEnvelope = env
	return state.Commit(repo, hooks.ApplyMessage, hooksApplyMap, true)
}

// VerifyHooks verifies the signature of the metadata env
// through dsse.VerifyEnvelope
func (r *Repository) VerifyHooks(state *hooks.HookState) error {
	h := state.HooksEnvelope
	payloadBytes, err := h.DecodeB64Payload()
	if err != nil {
		return err
	}

	sha256Hash := sha256.New()
	sha256Hash.Write(payloadBytes)
	sha256HashSum := sha256Hash.Sum(nil)

	targetsMetadata, err := state.GetTargetsMetadata(hooks.TargetsRoleName)
	if err != nil {
		return err
	}

	sha256HashSumGit := gitinterface.Hash(sha256HashSum)
	hooksHash := targetsMetadata.GetHooksField()
	if hooksHash != sha256HashSumGit.String() {
		return hooks.ErrHooksMetadataHashMismatch
	}

	return nil
}

// VerifyHookAccess checks whether the signer (a sslibdsse.Signer object) is
// authorized to load and use the hook associated with a particular stage or not.
func (r *Repository) VerifyHookAccess(state *hooks.HookState, signer sslibdsse.Signer, stage string) error {
	hooksMetadata, err := state.GetHooksMetadata()
	if err != nil {
		return err
	}

	keyID, err := signer.KeyID()
	if err != nil {
		return err
	}

	allowedKeys := hooksMetadata.Access[stage]
	if allowedKeys == nil {
		return nil
	}

	for _, key := range allowedKeys {
		if keyID == key {
			return nil
		}
	}
	return hooks.ErrHookAccessDenied
}

// LoadHooks should load the latest hooks metadata and load the hook files
// todo:change workflow to work with Lua and gVisor - return the bytestream
// instead of writing the file. The logic for deciding whether to write
// the file or not should be in gittuf-git/cmd
func (r *Repository) LoadHooks(signer sslibdsse.Signer) error {
	repo := r.GetGitRepository()
	hooksTip, err := repo.GetReference(hooks.HooksRef)
	if err != nil {
		if !errors.Is(err, gitinterface.ErrReferenceNotFound) {
			return fmt.Errorf("failed to get policy reference %s: %w", hooksTip, err)
		}
	}

	state, err := hooks.LoadCurrentState(repo)
	if err != nil {
		if !errors.Is(err, rsl.ErrRSLEntryNotFound) {
			return fmt.Errorf("failed to load hooks: %w", err)
		}
	}
	slog.Debug("Loaded current state")

	err = r.VerifyHooks(state)
	if err != nil {
		return err
	}
	slog.Debug("Verification successful.")

	hooksMetadata, err := state.GetHooksMetadata()
	if err != nil {
		return err
	}

	for filename, hookInfo := range hooksMetadata.HooksInfo {
		stage := hookInfo.Stage
		err := r.VerifyHookAccess(state, signer, stage)
		if err != nil {
			fmt.Println("Attempting to load ", stage, " hook with unauthorized key -- skipping...")
			continue
		}
		// convert string hash value to hash object for reading blob contents
		hookBlobID, err := gitinterface.NewHash(hookInfo.BlobID)
		hookContents, err := repo.ReadBlob(hookBlobID)
		if err != nil {
			return err
		}
		filename = "hooks/" + filename
		err = os.MkdirAll(filepath.Dir(filename), 0755)
		if err != nil {
			return err
		}

		err = os.WriteFile(filename, hookContents, 0600)
		if err != nil {
			return err
		}
	}

	slog.Debug("Loaded hooks files")
	return nil
}

// LoadHookByStage takes in the stage as a string arg, and builds ONLY the file associated with that stage.
// todo: might have to change workflow to return bytes instead of writing the file
func (r *Repository) LoadHookByStage(stage string) error {
	repo := r.GetGitRepository()
	hooksTip, err := repo.GetReference(hooks.HooksRef)
	if err != nil {
		if !errors.Is(err, gitinterface.ErrReferenceNotFound) {
			return fmt.Errorf("failed to get policy reference %s: %w", hooksTip, err)
		}
	}

	state, err := hooks.LoadCurrentState(repo)
	if err != nil {
		if !errors.Is(err, rsl.ErrRSLEntryNotFound) {
			return fmt.Errorf("failed to load hooks: %w", err)
		}
	}
	slog.Debug("Loaded current state")

	err = r.VerifyHooks(state)
	if err != nil {
		return err
	}

	hooksMetadata, err := state.GetHooksMetadata()
	if err != nil {
		return err
	}

	hookName := hooksMetadata.Bindings[stage]
	hookInfo := hooksMetadata.HooksInfo[hookName]
	// convert string hash value to hash object for reading blob contents
	hookBlobID, err := gitinterface.NewHash(hookInfo.BlobID)
	hookContents, err := repo.ReadBlob(hookBlobID)
	if err != nil {
		return err
	}
	filename := "hooks/" + hookName
	err = os.MkdirAll(filepath.Dir(filename), 0755)
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, hookContents, 0600)
	if err != nil {
		return err
	}

	fmt.Println("Loaded hook file for ", stage)
	return nil
}
