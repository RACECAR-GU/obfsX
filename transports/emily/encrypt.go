package emily

import (
	"os/exec"
	"bytes"
)
// ADDTEST
func encrypt(msg, pwd []byte) ([]byte, err) {
	cmd := exec.Command("gpg --armor --batch --passphrase \"" + string(pwd) + "\" -c")
	cmd.Stdin = bytes.NewReader(msg)
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	return out.bytes(), nil
}

func decrypt(msg, pwd []byte) ([]byte, err) {
	cmd := exec.Command("gpg --batch --decrypt --passphrase \"" + string(pwd) + "\"")
	cmd.Stdin = bytes.NewReader(msg)
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	return out.bytes(), nil
}
