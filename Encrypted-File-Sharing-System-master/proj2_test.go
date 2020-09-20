package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestGetUser(t *testing.T) {
	clear()

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	_, err = GetUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to get user", err)
		return
	}
	_, err = GetUser("bob", "password")
	if err == nil {
		t.Error("Retrieved user that does not exist", err)
		return
	}
}

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestSingleAppend(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v1 := []byte("Test should pass")
	err = u.AppendFile("file1", v1)
	if err != nil {
		t.Error("Failed to append", err)
		return
	}

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	v = append(v, v1...)
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestMultipleAppend(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v1 := []byte("First append")
	v = append(v, v1...)
	err = u.AppendFile("file1", v1)
	if err != nil {
		t.Error("Failed to append", err)
		return
	}

	v1 = []byte("Second append")
	v = append(v, v1...)
	err = u.AppendFile("file1", v1)
	if err != nil {
		t.Error("Failed to append", err)
		return
	}

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}

func TestCoverage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	u3, err := InitUser("c", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u4, err2 := InitUser("d", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u2.ReceiveFile("file1", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return

	}

	magic_string, err = u2.ShareFile("file1", "c")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u3.ReceiveFile("file1", "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v3, err := u3.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	magic_string, err = u3.ShareFile("file1", "d")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u4.ReceiveFile("file1", "c", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v4, err := u4.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}

	v2, err = u2.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("Shared file is not the same", v, v3)
		return
	}

	if !reflect.DeepEqual(v2, v4) {
		t.Error("Shared file is not the same", v, v3)
		return
	}

	err = u.RevokeFile("file1", "bob")

	if err != nil {
		t.Error("Failed revoke bob", err)
		return
	}

	v4, err = u4.LoadFile("file1")
	if err == nil {
		t.Error("u4 can still look at file", err)
		return
	}

	err = u4.AppendFile("file1", []byte("This is a test"))
	if err == nil {
		t.Error("u4 can still look at file", err)
		return
	}

}
func TestGetNone(t *testing.T) {
	clear()

	user, err1 := InitUser("a", "fubar")
	if err1 != nil {
		t.Error(err1)
		return
	}

	bob, err1 := InitUser("bob", "fubar")
	if err1 != nil {
		t.Error(err1)
		return
	}

	c, err1 := InitUser("c", "fubar")
	if err1 != nil {
		t.Error(err1)
		return
	}

	_, err2 := GetUser("alice", "fubar")
	if err2 == nil {
		t.Error("Should not be able to find Alice")
		return
	}

	v := []byte("This is a test")
	user.StoreFile("file1", v)

	_, err := user.LoadFile("file2")
	if err == nil {
		t.Error("Should not be able to load file2")
		return
	}

	_, err = bob.LoadFile("file1")
	if err == nil {
		t.Error("Bob should not have access")
		return
	}

	err = user.AppendFile("file2", v)
	if err == nil {
		t.Error("Cannot append to file that does not exist")
	}

	magicString, err := user.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = c.ReceiveFile("file1", "alice", magicString)
	if err == nil {
		t.Error("c should not be able to use b's magic string")
		return
	}

	magicString = magicString[1:] + "a"

	err = bob.ReceiveFile("file1", "alice", magicString)
	if err == nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	_, err = bob.LoadFile("file1")
	if err == nil {
		t.Error("Failed to download the file after sharing", err)
		return

	}

}

func TestCoverage2(t *testing.T) {
	clear()
	datastore := userlib.DatastoreGetMap()

	user, err1 := InitUser("alice", "fubar")
	if err1 != nil {
		t.Error(err1)
		return
	}

	file := userlib.RandomBytes(userlib.AESBlockSize * 7)
	user.StoreFile("file1", file)

	// Get user to check for userdata update.
	user, err2 := GetUser("alice", "fubar")
	if err2 != nil {
		t.Error(err2)
		return
	}

	var keys []userlib.UUID
	var vals [][]byte
	for k, v := range datastore {
		keys = append(keys, k)
		vals = append(vals, v)
	}

	errored := false
	for k := range keys {
		datastore[keys[k]] = userlib.RandomBytes(len(vals[k]))
		_, err := user.LoadFile("file1")
		if err != nil {
			errored = true
		}
		datastore[keys[k]] = vals[k]
	}

	if !errored {
		t.Error("Corrupted datastore but no failed file load.")
	}
}

func TestCoverage3(t *testing.T) {
	clear()

	a, err1 := InitUser("a", "fubar")
	if err1 != nil {
		t.Error(err1)
		return
	}

	b, err1 := InitUser("b", "fubar")
	if err1 != nil {
		t.Error(err1)
		return
	}

	c, err1 := InitUser("c", "fubar")
	if err1 != nil {
		t.Error(err1)
		return
	}

	v := []byte("This is a test")
	v10 := []byte("This is another test")
	a.StoreFile("file1", v)
	c.StoreFile("file1", v10)

	x, err := c.LoadFile("file1")
	if err != nil {
		t.Error(err)
		return
	}

	y, err := a.LoadFile("file1")
	if err != nil {
		t.Error(err)
		return
	}

	if reflect.DeepEqual(x, y) {
		t.Error("Downloaded file is not the same", x, y)
		return
	}

	ms, err := a.ShareFile("file1", "b")
	if err != nil {
		t.Error(err)
		return
	}

	err = b.ReceiveFile("file1", "a", ms)
	if err != nil {
		t.Error(err)
		return
	}

	err = b.AppendFile("file1", v)
	if err != nil {
		t.Error(err)
		return
	}

	file := userlib.RandomBytes(userlib.AESBlockSize * 7)
	a.StoreFile("file1", file)

	v2, err := b.LoadFile("file1")
	if err != nil {
		t.Error(err)
		return
	}

	if !reflect.DeepEqual(file, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}

	file = userlib.RandomBytes(userlib.AESBlockSize * 7)
	b.StoreFile("file1", file)

	v3, err := a.LoadFile("file1")
	if err != nil {
		t.Error(err)
		return
	}

	if !reflect.DeepEqual(file, v3) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}

	err = a.RevokeFile("file1", "b")
	if err != nil {
		t.Error(err)
		return
	}

	nfile := userlib.RandomBytes(userlib.AESBlockSize * 7)
	b.StoreFile("file1", nfile)

	v3, err = a.LoadFile("file1")
	if err != nil {
		t.Error(err)
		return
	}

	if reflect.DeepEqual(nfile, v3) {
		t.Error("Downloaded file is the same", nfile, v3)
		return
	}
}

func TestCoverage4(t *testing.T) {
	clear()

	v := []byte("This is a test")

	a := User{}

	a.StoreFile("file1", v)

	v2, err2 := a.LoadFile("file1")
	if err2 == nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}

}

func TestFileShare(t *testing.T) {
	clear()
	u, err := InitUser("a", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err = InitUser("b", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	_, err2 := u.ShareFile("file2", "b")
	if err2 == nil {
		t.Error("File name should not Exist", err2)
		return
	}
}
