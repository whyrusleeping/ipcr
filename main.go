package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"os"
	"syscall"

	ipfs "github.com/ipfs/go-ipfs-api"

	cli "github.com/urfave/cli/v2"

	"golang.org/x/crypto/ssh/terminal"
)

func main() {

	app := cli.NewApp()

	app.Commands = []*cli.Command{
		addCmd,
		getCmd,
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "error: ", err)
	}
}

var getCmd = &cli.Command{
	Name: "get",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "password",
			Usage: "specify password to encrypt file with",
		},
	},
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must specify file to get")
		}

		fcid := cctx.Args().First()

		encpw := cctx.String("password")
		if encpw == "" {
			fmt.Fprintln(os.Stderr, "Please enter password to decrypt data with:")
			pw, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return err
			}
			encpw = string(pw)
		}

		sh := ipfs.NewLocalShell()

		r, err := sh.Cat(fcid)
		if err != nil {
			return err
		}
		defer r.Close()

		encfi, err := decryptionWrap(encpw, r)
		if err != nil {
			return err
		}

		_, err = io.Copy(os.Stdout, encfi)
		if err != nil {
			return err
		}

		return nil
	},
}

var addCmd = &cli.Command{
	Name: "add",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "password",
			Usage: "specify password to encrypt file with",
		},
		&cli.Int64Flag{
			Name:  "seed",
			Usage: "specify a seed value for the encryption",
		},
	},
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must specify file to add")
		}

		fname := cctx.Args().First()
		st, err := os.Stat(fname)
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("can only add files right now (try putting it in an archive for now)")
		}

		fi, err := os.Open(fname)
		if err != nil {
			return err
		}

		encpw := cctx.String("password")
		if encpw == "" {
			fmt.Fprintln(os.Stderr, "Please enter password to encrypt data with:")
			pw, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return err
			}
			encpw = string(pw)
		}

		sval := cctx.Int64("seed")
		if sval == 0 {
			sval = rand.Int63()
		}

		sh := ipfs.NewLocalShell()

		encfi, err := encryptionWrap(sval, encpw, fi)
		if err != nil {
			return err
		}

		out, err := sh.AddWithOpts(encfi, false, true)
		if err != nil {
			return err
		}

		fmt.Fprintln(os.Stderr, "file encrypted and added: ", out)
		return nil
	},
}

func decryptionWrap(pw string, r io.Reader) (io.Reader, error) {
	buf := make([]byte, 8)

	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}

	iv := sha256.Sum256(buf)
	pwhash := sha256.Sum256([]byte(pw))

	blkc, err := aes.NewCipher(pwhash[:])
	if err != nil {
		return nil, err
	}

	dec := cipher.NewCFBDecrypter(blkc, iv[:blkc.BlockSize()])

	rbuf := make([]byte, 4096)

	er := &encReader{
		f: func(b []byte) (int, error) {
			l := len(b)
			if l > len(rbuf) {
				l = len(rbuf)
			}

			n, err := r.Read(rbuf[:l])
			if err != nil && err != io.EOF {
				return 0, err
			}

			dec.XORKeyStream(b[:n], rbuf[:n])

			return n, err
		},
	}

	return er, nil
}

type encReader struct {
	f func([]byte) (int, error)
}

func (e *encReader) Read(b []byte) (int, error) {
	return e.f(b)
}

func encryptionWrap(seed int64, pw string, r io.Reader) (io.Reader, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(seed))

	iv := sha256.Sum256(buf)
	pwhash := sha256.Sum256([]byte(pw))
	blkc, err := aes.NewCipher(pwhash[:])
	if err != nil {
		return nil, err
	}

	enc := cipher.NewCFBEncrypter(blkc, iv[:blkc.BlockSize()])

	rbuf := make([]byte, 4096)

	er := &encReader{
		f: func(b []byte) (int, error) {
			l := len(b)
			if l > len(rbuf) {
				l = len(rbuf)
			}
			n, err := r.Read(rbuf[:l])
			if err != nil {
				return 0, err
			}
			enc.XORKeyStream(b[:n], rbuf[:n])

			return n, nil
		},
	}

	return io.MultiReader(bytes.NewReader(buf), er), nil
}
