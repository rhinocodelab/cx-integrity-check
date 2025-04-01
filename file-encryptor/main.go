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
)

const (
	hardCodedKey = "ThisIsASecretKey1234567890123456" // 32-byte hardcoded key
	imagePath    = "/sda1/data/.gems.jpeg"
)

var directories = []string{
	"/sda1/data/apps/",
	"/sda1/data/basic/",
	"/sda1/data/core/",
	"/sda1/boot/",
}

type DBHash struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

func remountSDA1RW() error {
	fmt.Println("Remounting /sda1 as read-write")
	cmd := exec.Command("mount", "-o", "remount,rw", "/sda1")
	return cmd.Run()
}

func remountSDA1RO() {
	fmt.Println("Remounting /sda1 as read-only")
	cmd := exec.Command("mount", "-o", "remount,ro", "/sda1")
	cmd.Run()
}

func extractKeyFromImage() ([]byte, error) {
	tempKeyFile := "temp_key.txt"
	defer os.Remove(tempKeyFile)

	cmd := exec.Command("steghide", "extract", "-sf", imagePath, "-xf", tempKeyFile, "-p", "Sundyne@123")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to extract key from image: %v", err)
	}

	key, err := os.ReadFile(tempKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read extracted key: %v", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("extracted key must be 32 bytes, got %d bytes", len(key))
	}

	return key, nil
}

func encryptFileWithOpenSSL(filePath string, key []byte) error {
	iv := "1234567890123456" // 16 bytes for AES-256-CBC
	tempFile := filePath + ".tmp"

	cmd := exec.Command("openssl", "enc", "-aes-256-cbc",
		"-in", filePath,
		"-out", tempFile,
		"-K", fmt.Sprintf("%x", key),
		"-iv", iv)

	if err := cmd.Run(); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("encryption failed for %s: %v", filePath, err)
	}

	if err := os.Rename(tempFile, filePath); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to replace original file %s: %v", filePath, err)
	}

	return nil
}

func decryptFileWithOpenSSL(filePath string, key []byte) error {
	iv := "1234567890123456" // Must match encryption IV
	tempFile := filePath + ".tmp"

	cmd := exec.Command("openssl", "enc", "-aes-256-cbc", "-d",
		"-in", filePath,
		"-out", tempFile,
		"-K", fmt.Sprintf("%x", key),
		"-iv", iv)

	if err := cmd.Run(); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("decryption failed for %s: %v", filePath, err)
	}

	if err := os.Rename(tempFile, filePath); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to replace original file %s: %v", filePath, err)
	}

	return nil
}

func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open %s: %v", filePath, err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to calculate hash for %s: %v", filePath, err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// New AES-GCM encryption function for encrypt-image
func encryptFileWithAESGCM(key []byte, filePath string) error {
	plaintext, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", filePath, err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return os.WriteFile(filePath, ciphertext, 0644)
}

func updateHashFile(hashPath, dbPath string, key []byte, useAESGCM bool) error {
	newHash, err := calculateFileHash(dbPath)
	if err != nil {
		return err
	}

	dbHash := DBHash{
		Path: dbPath,
		Hash: newHash,
	}

	jsonData, err := json.MarshalIndent(dbHash, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal hash data: %v", err)
	}

	tempFile := hashPath + ".tmp"
	if err := os.WriteFile(tempFile, jsonData, 0644); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to write temporary hash file: %v", err)
	}

	if useAESGCM {
		if err := encryptFileWithAESGCM(key, tempFile); err != nil {
			os.Remove(tempFile)
			return err
		}
	} else {
		if err := encryptFileWithOpenSSL(tempFile, key); err != nil {
			os.Remove(tempFile)
			return err
		}
	}

	if err := os.Rename(tempFile, hashPath); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to replace hash file %s: %v", hashPath, err)
	}

	return nil
}

func processDirectory(dir string, operation string) error {
	dbPath := filepath.Join(dir, ".db.json")
	hashFile := fmt.Sprintf(".%s.json", filepath.Base(dir))
	hashPath := filepath.Join(dir, hashFile)

	files := []string{dbPath, hashPath}

	switch operation {
	case "encrypt-hard":
		for _, file := range files {
			if _, err := os.Stat(file); os.IsNotExist(err) {
				fmt.Printf("Skipping %s: file does not exist\n", file)
				continue
			}
			fmt.Printf("Encrypting %s with hardcoded key\n", file)
			if err := encryptFileWithOpenSSL(file, []byte(hardCodedKey)); err != nil {
				return err
			}
		}

	case "decrypt-hard":
		for _, file := range files {
			if _, err := os.Stat(file); os.IsNotExist(err) {
				fmt.Printf("Skipping %s: file does not exist\n", file)
				continue
			}
			fmt.Printf("Decrypting %s with hardcoded key\n", file)
			if err := decryptFileWithOpenSSL(file, []byte(hardCodedKey)); err != nil {
				return err
			}
		}

	case "encrypt-image":
		key, err := extractKeyFromImage()
		if err != nil {
			return err
		}
		// Encrypt .db.json with AES-GCM
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			fmt.Printf("Skipping %s: file does not exist\n", dbPath)
		} else {
			fmt.Printf("Encrypting %s with image-extracted key using AES-GCM\n", dbPath)
			if err := encryptFileWithAESGCM(key, dbPath); err != nil {
				return err
			}
		}

		// Update and encrypt hash file with AES-GCM
		if _, err := os.Stat(hashPath); os.IsNotExist(err) {
			fmt.Printf("Skipping %s: file does not exist\n", hashPath)
		} else {
			fmt.Printf("Updating and encrypting %s with image-extracted key using AES-GCM\n", hashPath)
			if err := updateHashFile(hashPath, dbPath, key, true); err != nil {
				return err
			}
		}

	default:
		return fmt.Errorf("unknown operation: %s", operation)
	}

	return nil
}

func main() {
	fs := flag.NewFlagSet("file-encryptor", flag.ExitOnError)

	operation := fs.String("op", "", "Operation to perform: encrypt-hard, decrypt-hard, encrypt-image")
	help := fs.Bool("help", false, "Display usage information")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -op <operation>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nEncrypts or decrypts .db.json and .%s.json files in specified directories\n", "directory")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nOperations:\n")
		fmt.Fprintf(os.Stderr, "  encrypt-hard: Encrypt files using a hardcoded key\n")
		fmt.Fprintf(os.Stderr, "  decrypt-hard: Decrypt files using a hardcoded key\n")
		fmt.Fprintf(os.Stderr, "  encrypt-image: Encrypt files using a key extracted from %s\n", imagePath)
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -op encrypt-hard   # Encrypt with hardcoded key\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -op decrypt-hard   # Decrypt with hardcoded key\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -op encrypt-image  # Encrypt with key from image\n", os.Args[0])
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		return
	}

	if *help || *operation == "" {
		fs.Usage()
		return
	}

	validOps := map[string]bool{
		"encrypt-hard":  true,
		"decrypt-hard":  true,
		"encrypt-image": true,
	}
	if !validOps[*operation] {
		fmt.Printf("Error: Invalid operation '%s'\n", *operation)
		fs.Usage()
		return
	}

	if err := remountSDA1RW(); err != nil {
		fmt.Println("Error remounting /sda1 as read-write:", err)
		return
	}
	defer remountSDA1RO()

	success := true
	for _, dir := range directories {
		fmt.Printf("\nProcessing directory: %s\n", dir)
		if err := processDirectory(dir, *operation); err != nil {
			fmt.Printf("Error processing %s: %v\n", dir, err)
			success = false
		}
	}

	if success {
		fmt.Printf("\nOperation '%s' completed successfully for all directories\n", *operation)
	} else {
		fmt.Printf("\nOperation '%s' failed for one or more directories\n", *operation)
	}
}
