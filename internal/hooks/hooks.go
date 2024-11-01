package hooks

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gittuf/gittuf/internal/gitinterface"
	"github.com/gittuf/gittuf/internal/policy"
	"github.com/gittuf/gittuf/internal/rsl"
	"github.com/gittuf/gittuf/internal/signerverifier/dsse"
	sslibdsse "github.com/gittuf/gittuf/internal/third_party/go-securesystemslib/dsse"
	"github.com/gittuf/gittuf/internal/tuf"
	"io/ioutil"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	HooksRef              = "refs/gittuf/hooks"
	DefaultCommitMessage  = "Create hooks ref"
	RootRoleName          = "root"
	TargetsRoleName       = "targets"
	metadataTreeEntryName = "metadata"
	HooksDir              = ".gittuf/hooks"
	hooksTreeEntryName    = "hooks"
	hooksRoleName         = "hooks"
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
	HooksEnvelope       *sslibdsse.Envelope
	DelegationEnvelopes map[string]*sslibdsse.Envelope
	RootPublicKeys      []tuf.Principal
	repository          *gitinterface.Repository
}

type HooksMetadata struct {
	HooksInfo map[string]*HooksInformation `json:"HooksInfo"`
	Bindings  map[string][]string          `json:"Bindings"`
}

type HooksInformation struct {
	SHA256Hash []byte   `json:"SHA256Hash"`
	BlobID     []byte   `json:"BlobID"`
	Stage      string   `json:"Stage"`
	Branches   []string `json:"Branches"`
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

func (r *regularSearcher) FindHooksEntriesInRange(firstEntry, lastEntry rsl.Entry) ([]*rsl.ReferenceEntry, error) {
	allPolicyEntries, _, err := rsl.GetReferenceEntriesInRangeForRef(r.repo, firstEntry.GetID(), lastEntry.GetID(), HooksRef)
	if err != nil {
		return nil, err
	}

	return allPolicyEntries, nil
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

	return state, nil
}

func LoadState(ctx context.Context, repo *gitinterface.Repository, requestedEntry *rsl.ReferenceEntry) (*StateWrapper, error) {
	searcher := newSearcher(repo)
	firstHooksEntry, err := searcher.FindFirstHooksEntry()
	if err != nil {
		if errors.Is(err, ErrPolicyNotFound) {
			return loadStateForEntry(repo, requestedEntry)
		}
		return nil, err
	}

	knows, err := repo.KnowsCommit(firstHooksEntry.ID, requestedEntry.ID)
	if err != nil {
		return nil, err
	}
	if knows {
		slog.Debug("knows")
		return loadStateForEntry(repo, requestedEntry)
	}

	initialHooksState, err := loadStateForEntry(repo, firstHooksEntry)
	if err != nil {
		return nil, err
	}

	return initialHooksState, nil
}

func LoadCurrentState(ctx context.Context, repo *gitinterface.Repository) (*StateWrapper, error) {
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

func InitializeHooksMetadata() *HooksMetadata {
	return &HooksMetadata{HooksInfo: make(map[string]*HooksInformation)}
}

// todo: change this to be more general, i.e. things like init hooks/targets metadata should go to another function
// todo: maybe titled "init" or something, and the initialize hooks/targets metadata should change to get
func (s *StateWrapper) Init(repo *gitinterface.Repository, commitMessage string, signCommit bool) error {
	if len(commitMessage) == 0 {
		commitMessage = DefaultCommitMessage
	}

	metadata := map[string]*sslibdsse.Envelope{}
	targetsMetadata := policy.InitializeTargetsMetadata()
	env, err := dsse.CreateEnvelope(targetsMetadata)
	if err != nil {
		return err
	}
	metadata[TargetsRoleName] = env

	hooksMetadata := InitializeHooksMetadata()
	env, err = dsse.CreateEnvelope(hooksMetadata)
	metadata[hooksRoleName] = env
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

	return s.Commit(repo, allTreeEntries, commitMessage, signCommit)
}

func (s *StateWrapper) GetHooksMetadata() (*HooksMetadata, error) {
	h := s.HooksEnvelope
	if h == nil {
		slog.Debug("Could not find requested metadata file; initializing hooks metadata")
		metadata := InitializeHooksMetadata()
		return metadata, nil
	}

	payloadBytes, err := h.DecodeB64Payload()
	if err != nil {
		return nil, err
	}

	hooksMetadata := &HooksMetadata{}
	if err = json.Unmarshal(payloadBytes, hooksMetadata); err != nil {
		return nil, err
	}

	return hooksMetadata, nil
}

func (s *StateWrapper) Commit(repo *gitinterface.Repository, allTreeEntries map[string]gitinterface.Hash, commitMessage string, sign bool) error {
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
	commitID, err := repo.Commit(hooksRootTreeID, HooksRef, commitMessage, sign)
	if err != nil {
		return err
	}

	// record changes to RSL
	newReferenceEntry := rsl.NewReferenceEntry(HooksRef, commitID)
	if err := newReferenceEntry.Commit(repo, true); err != nil {
		if !originalCommitID.IsZero() {
			return repo.ResetDueToError(err, HooksRef, originalCommitID)
		}

		return err
	}
	slog.Debug("RSL entry recording successful.")
	return nil
}

func (s *StateWrapper) Add(repo *gitinterface.Repository, hooksFilePath, stage, hookName string) error {
	// this function will copy files and their metadata information to HooksDir.
	// gittuf hooks commit will commit all the files and wipe? from this directory.

	hookFile, err := os.Open(hooksFilePath)
	if err != nil {
		return err
	}
	defer hookFile.Close()

	allTreeEntries := map[string]gitinterface.Hash{}

	hookFileContents, err := ioutil.ReadAll(hookFile)
	blobID, err := repo.WriteBlob(hookFileContents)
	if err != nil {
		return err
	}

	if hookName == "default" {
		hookName = filepath.Base(hooksFilePath)
	}

	allTreeEntries[path.Join(hooksTreeEntryName, filepath.Base(hooksFilePath))] = blobID

	// calculate hash to send to s.GenerateMetadataFor
	sha256Hash := sha256.New()
	sha256Hash.Write(hookFileContents)
	sha256HashSum := sha256Hash.Sum(nil)

	updatedHooksMetadata, err := s.GenerateMetadataFor(repo, hookName, stage, blobID, sha256HashSum)
	if err != nil {
		return err
	}
	// todo: encode updatedHooksMetadata using WriteBlob to include in the worktree and call repo.Init on
	metadata := map[string]*sslibdsse.Envelope{}
	env, err := dsse.CreateEnvelope(updatedHooksMetadata)
	metadata[hooksRoleName] = env

	envContents, err := json.Marshal(env)
	if err != nil {
		return err
	}

	blobID, err = repo.WriteBlob(envContents)
	if err != nil {
		return err
	}
	name := "hooks"
	allTreeEntries[path.Join(metadataTreeEntryName, name+".json")] = blobID
	commitMessage := "Add" + hookName

	return s.Commit(repo, allTreeEntries, commitMessage, true)
}

func (s *StateWrapper) GenerateMetadataFor(repo *gitinterface.Repository, hookName, stage string, blobID, sha256HashSum gitinterface.Hash) (*HooksMetadata, error) {
	currentMetadata, err := s.GetHooksMetadata()
	if err != nil {
		return nil, err
	}
	hookInfo := &HooksInformation{
		SHA256Hash: sha256HashSum,
		Stage:      stage,
		BlobID:     blobID,
	}
	// todo: this is currently rewriting the metadata -> you want to add to a list of new metadata
	currentMetadata.HooksInfo[hookName] = hookInfo
	// todo: here, add information about the branchID and overall Binding datastructure.
	return currentMetadata, nil
}
