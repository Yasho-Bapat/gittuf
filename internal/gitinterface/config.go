// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

var (
	getGitConfigFromCommand = execGitConfig // variable used to override in tests
)

// GetConfig parses the user's Git config. It shells out to the Git binary
// because go-git has difficulty combining local, global, and system configs
// while maintaining all of their fields.
// See: https://github.com/go-git/go-git/issues/508
//
// Deprecated: We only use this to check if signing is viable, we should find an
// alternative mechanism.
func getConfig() (map[string]string, error) {
	configReader, err := getGitConfigFromCommand()
	if err != nil {
		return nil, err
	}

	config := map[string]string{}

	s := bufio.NewScanner(configReader)
	for s.Scan() {
		raw := s.Text()
		data := strings.Split(raw, " ")
		if len(data) < 2 {
			continue
		}
		config[data[0]] = strings.Join(data[1:], " ")
	}

	return config, nil
}

func execGitConfig() (io.Reader, error) {
	cmd := exec.Command("git", "config", "--get-regexp", `.*`)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, stderr.String())
	}

	return stdout, nil
}

// GetGitConfig reads the applicable Git config for a repository and returns
// it. The "keys" for each config are normalized to lowercase.
func (r *Repository) GetGitConfig() (map[string]string, error) {
	stdOut, err := r.executor("config", "--get-regexp", `.*`).executeString()
	if err != nil {
		return nil, fmt.Errorf("unable to read Git config: %w", err)
	}

	config := map[string]string{}

	lines := strings.Split(strings.TrimSpace(stdOut), "\n")
	for _, line := range lines {
		split := strings.Split(line, " ")
		if len(split) < 2 {
			continue
		}
		config[strings.ToLower(split[0])] = strings.Join(split[1:], " ")
	}

	return config, nil
}

// SetGitConfig sets the specified key to the value locally for a repository.
func (r *Repository) SetGitConfig(key, value string) error {
	if _, err := r.executor("config", "--local", key, value).executeString(); err != nil {
		return fmt.Errorf("unable to set '%s' to '%s': %w", key, value, err)
	}

	return nil
}
