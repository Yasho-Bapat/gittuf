// SPDX-License-Identifier: Apache-2.0

package artifacts

import _ "embed"

//go:embed testdata/scripts/askpass.sh
var UnixAskpassScript []byte

//go:embed testdata/scripts/askpass.exe
var WindowsAskpassScript []byte
