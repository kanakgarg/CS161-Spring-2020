package proj2

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username   string
	Key        []byte
	PrivateKey userlib.PKEDecKey
	SignKey    userlib.DSSignKey
	SymEncKey  []byte
	MACKey     []byte
	FileMap    map[string]uuid.UUID
	KeyMap     map[uuid.UUID][]byte

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type File struct {
	NextAppend uuid.UUID
	Data       []byte
	Shared     *ShareTree
}

type Share struct {
	Key      []byte
	FileUUID uuid.UUID
}

type ShareTree struct {
	Root     string
	Children []*ShareTree
}

func (tree *ShareTree) add(shareName string, receiveName string) (err error) {
	var node *ShareTree
	node = treeDFS(tree, receiveName)

	if node != nil {
		return nil
	}

	node = treeDFS(tree, shareName)

	if node == nil {
		err = errors.New("Shared user cannot be found")
		return err
	}

	var recShare *ShareTree
	recShare = &ShareTree{
		Root:     receiveName,
		Children: []*ShareTree{},
	}

	node.Children = append(node.Children, recShare)
	return nil
}

func (tree *ShareTree) remove(shareName string, remName string) (err error) {

	if tree.Root != shareName {
		err = errors.New("Not original owner of file")
		return err
	}

	var node *ShareTree
	// node = treeDFS(tree, remName)
	// if node == nil {
	// 	return errors.New("Trying to remove user that does not have access")
	// }
	node = treeDFS(tree, shareName)

	var toRemove int
	toRemove = -1
	for index, child := range node.Children {
		if child.Root == remName {
			toRemove = index
			break
		}
	}

	if toRemove == -1 {
		return errors.New("Nonexistant remove")
	}
	node.Children = append(node.Children[:toRemove], node.Children[toRemove+1:]...)
	return nil
}

func treeDFS(t *ShareTree, name string) *ShareTree {
	if t.Root == name {
		return t
	}

	if len(t.Children) > 0 {
		for _, child := range t.Children {
			abc := treeDFS(child, name)
			if abc != nil {
				return abc
			}
		}
	}
	return nil
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Generate various keys
	key := userlib.Argon2Key([]byte(password), []byte(username), 16)
	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	symEncKey, err := userlib.HashKDF(key, []byte("SymEncKey"))
	if err != nil {
		return nil, err
	}
	symEncKey = symEncKey[:16]
	macKey, err := userlib.HashKDF(key, []byte("MACKey"))
	if err != nil {
		return nil, err
	}
	macKey = macKey[:16]

	// Set instance variables of User Struct
	userdata.Username = username
	userdata.Key = key
	userdata.PrivateKey = privateKey
	userdata.SignKey = signKey
	userdata.SymEncKey = symEncKey
	userdata.MACKey = macKey
	userdata.FileMap = make(map[string]uuid.UUID)
	userdata.KeyMap = make(map[uuid.UUID][]byte)

	// Store PublicKey and DSVerifyKey on the Keystore server
	err = userlib.KeystoreSet(username+" PK", publicKey)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+" DSK", verifyKey)
	if err != nil {
		return nil, err
	}

	// Encrypt and store User Struct on Datastore server
	userUUID := bytesToUUID(key)
	marshalledUser, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	// Enc(data)
	encryptedUser := userlib.SymEnc(symEncKey, userlib.RandomBytes(16), marshalledUser)
	// HMAC(Enc(data))
	macUser, err := userlib.HMACEval(macKey, encryptedUser)
	if err != nil {
		return nil, err
	}
	// HMAC(Enc(data)) | Enc(data)
	message := append(macUser, encryptedUser...)
	userlib.DatastoreSet(userUUID, message)

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Retrieve User struct from Datastore server
	key := userlib.Argon2Key([]byte(password), []byte(username), 16)
	userUUID := bytesToUUID(key)
	encMessage, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("User can't be found")
	}
	if len(encMessage) <= 64 {
		return nil, errors.New("User data was corrupted")
	}

	// Retrieve keys and data for verification
	symEncKey, err := userlib.HashKDF(key, []byte("SymEncKey"))
	if err != nil {
		return nil, err
	}
	symEncKey = symEncKey[:16]
	macKey, err := userlib.HashKDF(key, []byte("MACKey"))
	if err != nil {
		return nil, err
	}
	macKey = macKey[:16]
	encUser := encMessage[64:]
	hmacUser := encMessage[:64]
	macUser, err := userlib.HMACEval(macKey, encUser)
	if err != nil {
		return nil, err
	}

	// Verify MACS
	if !userlib.HMACEqual(macUser, hmacUser) {
		return nil, errors.New("User data was corrupted")
	}
	decUser := userlib.SymDec(symEncKey, encUser)
	err = json.Unmarshal(decUser, userdataptr)
	if err != nil {
		return nil, err
	}

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	fileUUID, exists := userdata.FileMap[filename]
	if !exists {
		fileUUID = uuid.New()
		userdata.FileMap[filename] = fileUUID
		userdata.KeyMap[fileUUID] = userlib.RandomBytes(16)
	}
	fileKey, _ := userdata.KeyMap[fileUUID]
	fileEncKey, _ := userlib.HashKDF(fileKey, []byte("SymEncKey"))
	fileEncKey = fileEncKey[:16]
	fileMacKey, _ := userlib.HashKDF(fileKey, []byte("MACKey"))
	fileMacKey = fileMacKey[:16]

	var filedata File
	if exists {
		encFile, _ := userlib.DatastoreGet(fileUUID)
		macFile := encFile[:64]
		encData := encFile[64:]
		macData, _ := userlib.HMACEval(fileMacKey, encData)
		_ = userlib.HMACEqual(macData, macFile)
		filedataDec := userlib.SymDec(fileEncKey, encData)
		var file File
		json.Unmarshal(filedataDec, &file)

		checkRcpt := treeDFS(file.Shared, userdata.Username)
		if checkRcpt == nil {
			fileUUID = uuid.New()
			userdata.FileMap[filename] = fileUUID
			userdata.KeyMap[fileUUID] = userlib.RandomBytes(16)
		}
		checkRcpt = nil

		filedata.Shared = file.Shared
	} else {
		filedata.Shared = &ShareTree{
			Root:     userdata.Username,
			Children: []*ShareTree{},
		}
	}
	filedata.NextAppend = uuid.New()
	filedata.Data = data

	marshalledFile, _ := json.Marshal(filedata)

	// Enc(data)
	encData := userlib.SymEnc(fileEncKey, userlib.RandomBytes(16), marshalledFile)
	// HMAC(Enc(data))
	macData, _ := userlib.HMACEval(fileMacKey, encData)
	// HMAC(Enc(data)) | Enc(data)
	message := append(macData, encData...)
	userlib.DatastoreSet(fileUUID, message)

	// Update changes to Userdata
	// Encrypt and store User Struct on Datastore server
	userUUID := bytesToUUID(userdata.Key)
	marshalledUser, _ := json.Marshal(userdata)
	// Enc(data)
	encryptedUser := userlib.SymEnc(userdata.SymEncKey, userlib.RandomBytes(16), marshalledUser)
	// HMAC(Enc(data))
	macUser, _ := userlib.HMACEval(userdata.MACKey, encryptedUser)
	// HMAC(Enc(data)) | Enc(data)
	userMessage := append(macUser, encryptedUser...)
	userlib.DatastoreSet(userUUID, userMessage)

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	fileUUID, ok := userdata.FileMap[filename]
	if !ok {
		return errors.New("File does not exist")
	}
	fileKey, ok := userdata.KeyMap[fileUUID]
	if !ok {
		return errors.New("File does not exist")
	}
	fileEncKey, _ := userlib.HashKDF(fileKey, []byte("SymEncKey"))
	fileEncKey = fileEncKey[:16]
	fileMacKey, _ := userlib.HashKDF(fileKey, []byte("MACKey"))
	fileMacKey = fileMacKey[:16]

	encFile, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return errors.New("File not found")
	}

	check := true
	var file File
	for ok {
		if len(encFile) <= 64 {
			return errors.New("File was corrupted")
		}
		macFile := encFile[:64]
		encData := encFile[64:]
		macData, err := userlib.HMACEval(fileMacKey, encData)
		if err != nil {
			return err
		}
		unmodified := userlib.HMACEqual(macData, macFile)
		if !unmodified {
			return errors.New("File was corrupted")
		}
		filedata := userlib.SymDec(fileEncKey, encData)
		json.Unmarshal(filedata, &file)
		if check {
			checkRcpt := treeDFS(file.Shared, userdata.Username)
			if checkRcpt == nil {
				return errors.New("User does not have permission")
			}
			checkRcpt = nil
			check = false
		}
		encFile, ok = userlib.DatastoreGet(file.NextAppend)
	}
	fileUUID = file.NextAppend

	var nextFiledata File
	nextFiledata.NextAppend = uuid.New()
	nextFiledata.Data = data
	// nextFiledata.Shared = file.Shared
	marshalledFile, _ := json.Marshal(nextFiledata)

	// Enc(data)
	encData := userlib.SymEnc(fileEncKey, userlib.RandomBytes(16), marshalledFile)
	// HMAC(Enc(data))
	macData, _ := userlib.HMACEval(fileMacKey, encData)
	// HMAC(Enc(data)) | Enc(data)
	message := append(macData, encData...)
	userlib.DatastoreSet(fileUUID, message)

	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	fileUUID, ok := userdata.FileMap[filename]
	if !ok {
		return nil, errors.New("File does not exist 1 ")
	}
	fileKey, ok := userdata.KeyMap[fileUUID]
	if !ok {
		return nil, errors.New("File does not exit 2 ")
	}
	fileEncKey, _ := userlib.HashKDF(fileKey, []byte("SymEncKey"))
	fileEncKey = fileEncKey[:16]
	fileMacKey, _ := userlib.HashKDF(fileKey, []byte("MACKey"))
	fileMacKey = fileMacKey[:16]

	encFile, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return nil, errors.New("File not found")
	}
	if len(encFile) <= 64 {
		return nil, errors.New("File was corrupted")
	}
	macFile := encFile[:64]
	encData := encFile[64:]
	macData, err := userlib.HMACEval(fileMacKey, encData)
	if err != nil {
		return nil, err
	}
	unmodified := userlib.HMACEqual(macData, macFile)
	if !unmodified {
		return nil, errors.New("File was corrupted")
	}
	filedata := userlib.SymDec(fileEncKey, encData)
	var file File
	json.Unmarshal(filedata, &file)

	checkRcpt := treeDFS(file.Shared, userdata.Username)
	if checkRcpt == nil {
		return nil, errors.New("User does not have permission")
	}
	checkRcpt = nil

	appendedData, ok, err := userdata.getAppends(file, fileEncKey, fileMacKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		data = file.Data
	} else {
		data = append(file.Data, appendedData...)
	}

	return data, nil
}

func (userdata *User) getAppends(file File, fileEncKey []byte, fileMacKey []byte) (data []byte, ok bool, err error) {
	retFile, ok := userlib.DatastoreGet(file.NextAppend)
	if !ok {
		return nil, false, nil
	}
	var nextFile File
	for ok {
		macFile := retFile[:64]
		encData := retFile[64:]
		macData, err := userlib.HMACEval(fileMacKey, encData)
		if err != nil {
			return data, false, err
		}
		unmodified := userlib.HMACEqual(macData, macFile)
		if !unmodified {
			return data, false, errors.New("File was corrupted")
		}
		filedata := userlib.SymDec(fileEncKey, encData)
		json.Unmarshal(filedata, &nextFile)

		data = append(data, nextFile.Data...)
		file = nextFile
		retFile, ok = userlib.DatastoreGet(file.NextAppend)
	}

	return data, true, nil

}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	//retrieve file UUID
	fileUUID, ok := userdata.FileMap[filename]
	if !ok {
		return "", errors.New("File does not exist")
	}
	fileKey, ok := userdata.KeyMap[fileUUID]
	if !ok {
		return "", errors.New("File does not exit")
	}
	fileEncKey, _ := userlib.HashKDF(fileKey, []byte("SymEncKey"))
	fileEncKey = fileEncKey[:16]
	fileMacKey, _ := userlib.HashKDF(fileKey, []byte("MACKey"))
	fileMacKey = fileMacKey[:16]

	//retrieve recipient public key
	publicKey, ok := userlib.KeystoreGet(recipient + " PK")
	if !ok {
		return "", errors.New("No public key found")
	}

	//retrieve my digital signature
	dSig := userdata.SignKey
	var share Share
	share.Key = fileKey
	share.FileUUID = fileUUID
	shareStruct, err := json.Marshal(share)
	if err != nil {
		return "", err
	}
	pke, err := userlib.PKEEnc(publicKey, shareStruct)
	if err != nil {
		return "", err
	}

	postSign, err := userlib.DSSign(dSig, pke)
	if err != nil {
		return "", err
	}

	magic_string = hex.EncodeToString(append(postSign, pke...))

	encFile, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return "", errors.New("File not found")
	}
	if len(encFile) <= 64 {
		return "", errors.New("File was corrupted")
	}
	macFile := encFile[:64]
	encData := encFile[64:]
	macData, err := userlib.HMACEval(fileMacKey, encData)
	if err != nil {
		return "", err
	}
	unmodified := userlib.HMACEqual(macData, macFile)
	if !unmodified {
		return "", errors.New("File was corrupted")
	}
	filedata := userlib.SymDec(fileEncKey, encData)
	var file File
	json.Unmarshal(filedata, &file)

	err = file.Shared.add(userdata.Username, recipient)
	if err != nil {
		return "", err
	}

	marshalledFile, _ := json.Marshal(file)
	// Enc(data)
	encData = userlib.SymEnc(fileEncKey, userlib.RandomBytes(16), marshalledFile)
	// HMAC(Enc(data))
	macData, _ = userlib.HMACEval(fileMacKey, encData)
	// HMAC(Enc(data)) | Enc(data)
	message := append(macData, encData...)
	userlib.DatastoreSet(fileUUID, message)

	return magic_string, nil

}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	magic_byte, err := hex.DecodeString(magic_string)
	if len(magic_byte) <= 256 {
		return errors.New("Magic_string was corrupted")
	}
	if err != nil {
		return err
	}
	verifyKeySender, ok := userlib.KeystoreGet(sender + " DSK")
	if !ok {
		return errors.New("Could not find sender")
	}
	signature := magic_byte[:256]
	encData := magic_byte[256:]
	err = userlib.DSVerify(verifyKeySender, encData, signature)
	if err != nil {
		return errors.New("Could not verify sender")
	}
	decData, err := userlib.PKEDec(userdata.PrivateKey, encData)
	var shareStruct Share
	err = json.Unmarshal(decData, &shareStruct)
	if err != nil {
		return err
	}
	fileUUID := shareStruct.FileUUID
	fileKey := shareStruct.Key

	_, ok = userdata.FileMap[filename]
	if ok {
		return errors.New("File already exists")
	}
	userdata.FileMap[filename] = fileUUID
	userdata.KeyMap[fileUUID] = fileKey
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	fileUUID, ok := userdata.FileMap[filename]
	if !ok {
		return errors.New("File does not exist")
	}
	fileKey, ok := userdata.KeyMap[fileUUID]
	if !ok {
		return errors.New("File does not exit")
	}
	fileEncKey, _ := userlib.HashKDF(fileKey, []byte("SymEncKey"))
	fileEncKey = fileEncKey[:16]
	fileMacKey, _ := userlib.HashKDF(fileKey, []byte("MACKey"))
	fileMacKey = fileMacKey[:16]

	encFile, ok := userlib.DatastoreGet(fileUUID)
	if len(encFile) <= 64 {
		return errors.New("File was corrupted")
	}
	if !ok {
		return errors.New("File not found")
	}
	macFile := encFile[:64]
	encData := encFile[64:]
	macData, err := userlib.HMACEval(fileMacKey, encData)
	if err != nil {
		return err
	}
	unmodified := userlib.HMACEqual(macData, macFile)
	if !unmodified {
		return errors.New("File was corrupted")
	}
	filedata := userlib.SymDec(fileEncKey, encData)
	var file File
	json.Unmarshal(filedata, &file)

	err = file.Shared.remove(userdata.Username, target_username)
	if err != nil {
		return errors.New("Revoked user does not exist")
	}

	marshalledFile, _ := json.Marshal(file)
	// Enc(data)
	encData = userlib.SymEnc(fileEncKey, userlib.RandomBytes(16), marshalledFile)
	// HMAC(Enc(data))
	macData, _ = userlib.HMACEval(fileMacKey, encData)
	// HMAC(Enc(data)) | Enc(data)
	message := append(macData, encData...)
	userlib.DatastoreSet(fileUUID, message)

	return nil
}
