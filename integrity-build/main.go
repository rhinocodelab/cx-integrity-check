package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type FileHash struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

type DBHash struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

func saveDBHash(dbPath string, key []byte, encrypt bool) (string, error) {
	hash, err := calculateFileHash(dbPath)
	if err != nil {
		return "", err
	}

	dir := filepath.Dir(dbPath)
	baseName := filepath.Base(dir)
	hashFileName := fmt.Sprintf(".%s.json", baseName)
	hashFilePath := filepath.Join(dir, hashFileName)

	dbHash := DBHash{
		Path: dbPath,
		Hash: hash,
	}

	jsonData, err := json.MarshalIndent(dbHash, "", "  ")
	if err != nil {
		return "", err
	}

	if encrypt {
		encryptedData, err := encryptData(key, jsonData)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(hashFilePath, encryptedData, 0644); err != nil {
			return "", err
		}
	} else {
		if err := os.WriteFile(hashFilePath, jsonData, 0644); err != nil {
			return "", err
		}
	}
	return hashFilePath, nil
}

func remountSDA1RW() error {
	cmd := exec.Command("mount", "-o", "remount,rw", "/sda1")
	return cmd.Run()
}

func remountSDA1RO() {
	cmd := exec.Command("mount", "-o", "remount,ro", "/sda1")
	cmd.Run()
}

func extractKeyFromImage(imagePath string) ([]byte, error) {
	tempKeyFile := "extracted_key.txt"
	cmd := exec.Command("steghide", "extract", "-sf", imagePath, "-xf", tempKeyFile, "-p", "Sundyne@123")
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	defer os.Remove(tempKeyFile)

	return os.ReadFile(tempKeyFile)
}

func encryptData(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func encryptFile(key []byte, filePath string, encrypt bool) error {
	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	if encrypt {
		ciphertext, err := encryptData(key, plaintext)
		if err != nil {
			return err
		}
		return os.WriteFile(filePath, ciphertext, 0644)
	}
	return nil // If not encrypting, leave the file as is
}

func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func scanAndSaveHashes(rootPath string, encrypt bool) error {
	var fileHashes []FileHash

	// Define files to exclude
	dbPath := filepath.Join(rootPath, ".db.json")
	baseName := filepath.Base(rootPath)
	hashFileName := fmt.Sprintf(".%s.json", baseName)
	hashFilePath := filepath.Join(rootPath, hashFileName)

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && path != rootPath {
			return filepath.SkipDir
		}
		// Skip .db.json and .apps.json (or similar)
		if !info.IsDir() && path != dbPath && path != hashFilePath {
			hash, err := calculateFileHash(path)
			if err != nil {
				return err
			}
			fileHashes = append(fileHashes, FileHash{Path: path, Hash: hash})
			fmt.Printf("Added file to hash list: %s (hash: %s)\n", path, hash)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Remove existing .db.json if it exists
	_ = os.Remove(dbPath)

	jsonData, err := json.MarshalIndent(fileHashes, "", "  ")
	if err != nil {
		return err
	}

	fmt.Printf("Writing .db.json to %s\n", dbPath)
	return os.WriteFile(dbPath, jsonData, 0644)
}

func createFlagFile() error {
	flagFilePath := "/data/.inxstatus"
	flagContent := fmt.Sprintf("Timestamp: %s\nSystem Info: %s\n", time.Now().Format(time.RFC3339), os.Getenv("HOSTNAME"))
	return os.WriteFile(flagFilePath, []byte(flagContent), 0644)
}

func flagExists() bool {
	_, err := os.Stat("/data/.inxstatus")
	return err == nil
}

func main() {
	fs := flag.NewFlagSet("integrity-build", flag.ExitOnError)

	encryptDB := fs.Bool("encrypt-db", true, "Encrypt .db.json file")
	encryptHash := fs.Bool("encrypt-hash", true, "Encrypt .apps.json file")
	help := fs.Bool("help", false, "Display usage information")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s [options]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nBuilds integrity files (.db.json and .apps.json) for specified directories\n")
		fmt.Fprintf(os.Stderr, "using a key extracted from /sda1/data/.gems\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s                  # Build with both files encrypted (default)\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -encrypt-db=false # Build with .db.json unencrypted\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -encrypt-hash=false -encrypt-db=false # Build with both files unencrypted\n", os.Args[0])
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		return
	}

	if *help {
		fs.Usage()
		return
	}

	if flagExists() {
		fmt.Println("Flag file detected. Integrity check already completed. Exiting.")
		return
	}

	if err := remountSDA1RW(); err != nil {
		fmt.Println("Error remounting /sda1:", err)
		remountSDA1RO()
		return
	}
	defer remountSDA1RO()

	imagePath := "/sda1/data/.gems.jpeg"

	key, err := extractKeyFromImage(imagePath)
	if err != nil {
		fmt.Println("Error extracting key from image:", err)
		return
	}

	directories := []string{
		"/sda1/data/apps/",
		"/sda1/data/basic/",
		"/sda1/data/core/",
		"/sda1/boot/",
	}

	type Result struct {
		Dir string
		Err error
	}
	resultChan := make(chan Result, len(directories))
	sem := make(chan struct{}, 2)

	for _, dir := range directories {
		go func(dir string) {
			sem <- struct{}{}
			defer func() { <-sem }()

			fmt.Printf("Processing directory: %s (in parallel)\n", dir)

			if err := scanAndSaveHashes(dir, *encryptDB); err != nil {
				resultChan <- Result{Dir: dir, Err: fmt.Errorf("error scanning %s: %v", dir, err)}
				return
			}

			dbPath := filepath.Join(dir, ".db.json")
			if err := encryptFile(key, dbPath, *encryptDB); err != nil {
				resultChan <- Result{Dir: dir, Err: fmt.Errorf("error encrypting %s: %v", dbPath, err)}
				return
			}

			hashFilePath, err := saveDBHash(dbPath, key, *encryptHash)
			if err != nil {
				resultChan <- Result{Dir: dir, Err: fmt.Errorf("error saving/encrypting hash file for %s: %v", dbPath, err)}
				return
			}

			resultChan <- Result{Dir: dir, Err: nil}
			fmt.Printf("Successfully created %s (encrypted: %v)\n", hashFilePath, *encryptHash)
		}(dir)
	}

	success := true
	for i := 0; i < len(directories); i++ {
		res := <-resultChan
		if res.Err != nil {
			fmt.Println(res.Err)
			success = false
		}
	}
	close(resultChan)

	if success {
		fmt.Printf("All directories processed successfully (DB encrypted: %v, Hash encrypted: %v)\n", *encryptDB, *encryptHash)
		createFlagFile()
	} else {
		fmt.Println("Some directories failed to process")
	}
}
