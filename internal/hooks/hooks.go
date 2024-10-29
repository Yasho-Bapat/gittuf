package hooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gittuf/gittuf/internal/gitinterface"
	"github.com/gittuf/gittuf/internal/policy"
	"github.com/gittuf/gittuf/internal/rsl"
	"github.com/gittuf/gittuf/internal/signerverifier/dsse"
	sslibdsse "github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/dsse"
	"github.com/gittuf/gittuf/internal/tuf"
	tufv01 "github.com/gittuf/gittuf/internal/tuf/v01"
	"log/slog"
	"path"
	"strings"
)

const (
	HooksRef              = "refs/gittuf/hooks"
	DefaultCommitMessage  = "Create hooks ref"
	RootRoleName          = "root"
	TargetsRoleName       = "targets"
	metadataTreeEntryName = "metadata"
)

var (
	ErrMetadataNotFound           = errors.New("unable to find requested metadata file; has it been initialized?")
	ErrDanglingDelegationMetadata = errors.New("unreachable targets metadata found")
	ErrPolicyNotFound             = errors.New("cannot find policy")
	ErrUnableToMatchRootKeys      = errors.New("unable to match root public keys, gittuf policy is in a broken state")
	ErrNotAncestor                = errors.New("cannot apply changes since policy is not an ancestor of the policy staging")
)

// Hooks metadata should be encoded on existing policy metadata
// We can have a default policy that protects the hooks ref, and use this
// policy to encode the metadata

// TODO: check how to initialize a default policy and reserve the name.
// Use this policy to add hook path, key ids, etc.
// policy.AddDelegation or policy.InitializeTargetsMetadata
// check out policy/helpers_test.go, policy/policy_test.go and policy/targets_test.go
// for information about how to init

type StateWrapper struct {
	RootEnvelope        *sslibdsse.Envelope
	TargetsEnvelope     *sslibdsse.Envelope
	DelegationEnvelopes map[string]*sslibdsse.Envelope
	RootPublicKeys      []tuf.Principal
	repository          *gitinterface.Repository
}

type HooksState struct {
	RootEnvelope        *sslibdsse.Envelope
	TargetsEnvelope     *sslibdsse.Envelope
	DelegationEnvelopes map[string]*sslibdsse.Envelope
	RootPublicKeys      []tuf.Principal
	repository          *gitinterface.Repository
}

type searcher interface {
	FindHooksEntryFor(entry rsl.Entry) (*rsl.ReferenceEntry, error)
	FindFirstHooksEntry() (*rsl.ReferenceEntry, error)
}

type regularSearcher struct {
	repo *gitinterface.Repository
}

func newSearcher(repo *gitinterface.Repository) *regularSearcher {
	return &regularSearcher{repo: repo}
}
func (r *regularSearcher) FindHooksEntryFor(entry rsl.Entry) (*rsl.ReferenceEntry, error) {
	// If the requested entry itself is for the policy ref, return as is
	if entry, isReferenceEntry := entry.(*rsl.ReferenceEntry); isReferenceEntry && entry.RefName == HooksRef {
		slog.Debug(fmt.Sprintf("Initial entry '%s' is for gittuf policy, setting that as current policy...", entry.GetID().String()))
		return entry, nil
	}

	policyEntry, _, err := rsl.GetLatestReferenceEntry(r.repo, rsl.ForReference(HooksRef), rsl.BeforeEntryID(entry.GetID()))
	if err != nil {
		if errors.Is(err, rsl.ErrRSLEntryNotFound) {
			slog.Debug(fmt.Sprintf("No policy found before initial entry '%s'", entry.GetID().String()))
			return nil, ErrPolicyNotFound
		}

		// Any other err must be returned
		return nil, err
	}

	return policyEntry, nil
}

func (r *regularSearcher) FindFirstHooksEntry() (*rsl.ReferenceEntry, error) {
	entry, _, err := rsl.GetFirstReferenceEntryForRef(r.repo, HooksRef)
	if err != nil {
		if errors.Is(err, rsl.ErrRSLEntryNotFound) {
			// we don't have a policy entry yet
			return nil, ErrPolicyNotFound
		}
		return nil, err
	}

	return entry, nil
}

func (s *StateWrapper) GetRootMetadata() (tuf.RootMetadata, error) {
	payloadBytes, err := s.RootEnvelope.DecodeB64Payload()
	if err != nil {
		return nil, err
	}

	rootMetadata := &tufv01.RootMetadata{}
	if err := json.Unmarshal(payloadBytes, rootMetadata); err != nil {
		return nil, err
	}
	return rootMetadata, nil
}

func loadStateForEntry(repo *gitinterface.Repository, entry *rsl.ReferenceEntry) (*StateWrapper, error) {
	if entry.RefName != HooksRef {
		return nil, rsl.ErrRSLEntryDoesNotMatchRef
	}

	commitTreeID, err := repo.GetCommitTreeID(entry.TargetID)
	if err != nil {
		return nil, err
	}

	allTreeEntries, err := repo.GetAllFilesInTree(commitTreeID)
	if err != nil {
		return nil, err
	}

	state := &StateWrapper{repository: repo}

	for name, blobID := range allTreeEntries {
		contents, err := repo.ReadBlob(blobID)
		if err != nil {
			return nil, err
		}

		// We have this conditional because once upon a time we used to store
		// the root keys on disk as well; now we just get them from the root
		// metadata file. We ignore the keys on disk in the old policy states.
		if strings.HasPrefix(name, metadataTreeEntryName+"/") {
			env := &sslibdsse.Envelope{}
			if err := json.Unmarshal(contents, env); err != nil {
				return nil, err
			}

			metadataName := strings.TrimPrefix(name, metadataTreeEntryName+"/")
			switch metadataName {
			case fmt.Sprintf("%s.json", RootRoleName):
				state.RootEnvelope = env

			case fmt.Sprintf("%s.json", TargetsRoleName):
				state.TargetsEnvelope = env

			default:
				if state.DelegationEnvelopes == nil {
					state.DelegationEnvelopes = map[string]*sslibdsse.Envelope{}
				}

				state.DelegationEnvelopes[strings.TrimSuffix(metadataName, ".json")] = env
			}
		}
	}
	rootMetadata, err := state.GetRootMetadata()
	if err != nil {
		return nil, err
	}

	rootPrincipals, err := rootMetadata.GetRootPrincipals()
	if err != nil {
		return nil, err
	}
	state.RootPublicKeys = rootPrincipals

	return state, nil
}

func LoadState(ctx context.Context, repo *gitinterface.Repository, requestedEntry *rsl.ReferenceEntry) (*StateWrapper, error) {
	searcher := newSearcher(repo)
	firstHooksEntry, err := searcher.FindFirstHooksEntry()
	if err != nil {
		if errors.Is(err, rsl.ErrRSLEntryNotFound) {
			return loadStateForEntry(repo, requestedEntry)
		}
		return nil, err
	}

	knows, err := repo.KnowsCommit(firstHooksEntry.ID, requestedEntry.ID)
	if err != nil {
		return nil, err
	}
	if knows {
		return loadStateForEntry(repo, requestedEntry)
	}

	initialHooksState, err := loadStateForEntry(repo, firstHooksEntry)
	if err != nil {
		return nil, err
	}

	// TODO: skipping for now
	//if err := initialHooksState.Verify(ctx); err != nil {
	//	return nil, fmt.Errorf("requested state has invalidly signed metadata: %w", err)
	//}
	return initialHooksState, nil
}

func LoadCurrentState(ctx context.Context, repo *gitinterface.Repository, ref string) (*StateWrapper, error) {
	entry, _, err := rsl.GetLatestReferenceEntry(repo, rsl.ForReference(HooksRef))
	if err != nil {
		return nil, err
	}
	return LoadState(ctx, repo, entry)
}

// LoadFirstState returns the State corresponding to the first Hooks commit.
// Verification of RoT is skipped since it is the initial commit.
func LoadFirstState(ctx context.Context, repo *gitinterface.Repository) (*StateWrapper, error) {
	firstEntry, _, err := rsl.GetFirstReferenceEntryForRef(repo, HooksRef)
	if err != nil {
		return nil, err
	}
	return LoadState(ctx, repo, firstEntry)
}
func (s *StateWrapper) Commit(repo *gitinterface.Repository, commitMessage string, signCommit bool) error {
	if len(commitMessage) == 0 {
		commitMessage = DefaultCommitMessage
	}

	metadata := map[string]*sslibdsse.Envelope{}
	targetsMetadata := policy.InitializeTargetsMetadata()
	env, err := dsse.CreateEnvelope(targetsMetadata)
	metadata[TargetsRoleName] = env

	// What do s.DelegationEnvelopes do?

	allTreeEntries := map[string]gitinterface.Hash{}

	for name, env := range metadata {
		envContents, err := json.Marshal(env)
		if err != nil {
			return err
		}

		blobID, err := repo.WriteBlob(envContents)
		if err != nil {
			return err
		}

		allTreeEntries[path.Join(metadataTreeEntryName, name+".json")] = blobID
	}

	treeBuilder := gitinterface.NewTreeBuilder(repo)
	hooksRootTreeID, err := treeBuilder.WriteRootTreeFromBlobIDs(allTreeEntries)
	if err != nil {
		return err
	}

	originalCommitID, err := repo.GetReference(HooksRef)
	if err != nil {
		if !errors.Is(err, gitinterface.ErrReferenceNotFound) {
			return err
		}
	}

	commitID, err := repo.Commit(hooksRootTreeID, HooksRef, commitMessage, signCommit)
	if err != nil {
		return err
	}

	// record changes to RSL
	newReferenceEntry := rsl.NewReferenceEntry(HooksRef, commitID)
	if err := newReferenceEntry.Commit(repo, signCommit); err != nil {
		if !originalCommitID.IsZero() {
			return repo.ResetDueToError(err, HooksRef, originalCommitID)
		}

		return err
	}
	return nil
}
