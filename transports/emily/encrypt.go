package emily

import (
	"os/exec"
	"bytes"
)

func encrypt(msg []byte, to string, keyring raven_keyring) ([]byte, error) {

	buf := bytes.NewBuffer(nil)
	armor_w, err := armor.Encode(buf, "PGP MESSAGE", make(map[string]string))
	if err != nil {
		return nil, err
	}

	keypair, ok := keyring[to]
	if !ok {
		logError("cannot find keypair for recipient: ", to)
		return nil, fmt.Errorf("cannot find keypair for recipient '%v'", to)
	}

	pubKey := decodePublicKey(keypair)
	privKey := decodePrivateKey(keypair)
	dst := createEntityFromKeys(pubKey, privKey)

	w, err := openpgp.Encrypt(armor_w, []*openpgp.Entity{dst}, nil, nil, nil)
	if err != nil {
		logError("cannot encrypt: ", err)
		return nil, err
	}
	defer w.Close()

	/*
		// TODO: remove this... was for symmetric case
			w, err := openpgp.SymmetricallyEncrypt(armor_w, pass, nil, nil)
			if err != nil {
				return nil, err
			}
			defer w.Close()
	*/

	_, err = w.Write(msg)
	if err != nil {
		return nil, err
	}

	w.Close()
	armor_w.Close()

	return buf.Bytes(), nil
}

func decrypt(raw []byte, keyring raven_keyring, self string) ([]byte, error) {

	pubKey := decodePublicKey(keyring[self])
	privKey := decodePrivateKey(keyring[self])

	entity := createEntityFromKeys(pubKey, privKey)

	buff := bytes.NewBuffer(raw)

	block, err := armor.Decode(buff)
	if err != nil {
		return nil, err
	}
	if block.Type != "PGP MESSAGE" { // NEXT: Make this a const
		return nil, io.EOF
	}

	var entityList openpgp.EntityList
	entityList = append(entityList, entity)

	md, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	/*
		failed := false
		prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			if failed {
				return nil, fmt.Errorf("decryption failed")
			}
			failed = true
			return []byte(keyring[self].PrivateKey), nil
			//return []byte("raven_is_cool"), nil
		}

		md, err := openpgp.ReadMessage(block.Body, nil, prompt, nil)
	*/
	if err != nil {
		logInfo("could not decrypt: likely a dummy message: ", err)
		return nil, io.EOF
	} else {
		logDebug("successfully decrypted GPG message")
	}

	res, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("Failed parsing: %s", err)
	} else {
		logDebug("read body of decrypted GPG message")
	}

	return res, nil
}
