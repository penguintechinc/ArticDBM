package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"

	"github.com/go-redis/redis/v8"
	"gopkg.in/ldap.v2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

type Config struct {
	AuthMethod string `yaml:"auth_method"` // "ldap" or "redis"
	LDAP       struct {
		Server   string `yaml:"server"`
		Port     int    `yaml:"port"`
		BindDN   string `yaml:"bind_dn"`
		Password string `yaml:"password"`
		BaseDN   string `yaml:"base_dn"`
	} `yaml:"ldap"`
	Redis struct {
		Address  string `yaml:"address"`
		Password string `yaml:"password"`
		DB       int    `yaml:"db"`
	} `yaml:"redis"`
}

var config Config

type UserValidator interface {
	Validate(username string) bool
}

type LDAPValidator struct{}

func (v *LDAPValidator) Validate(username string) bool {
	fmt.Println("Validating user with LDAP...")
	ldapConn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", config.LDAP.Server, config.LDAP.Port))
	if err != nil {
		fmt.Println("Error connecting to LDAP server:", err)
		return false
	}
	defer ldapConn.Close()

	err = ldapConn.Bind(config.LDAP.BindDN, config.LDAP.Password)
	if err != nil {
		fmt.Println("Error binding to LDAP server:", err)
		return false
	}

	searchRequest := ldap.NewSearchRequest(
		config.LDAP.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", username), // Use the username in the search filter
		[]string{"dn", "cn", "mail"},
		nil,
	)
	_, err = ldapConn.Search(searchRequest)
	if err != nil {
		fmt.Println("Error searching LDAP:", err)
		return false
	}

	fmt.Println("User found in LDAP")
	return true
}

type RedisValidator struct{}

func (v *RedisValidator) Validate(username string) bool {
	fmt.Println("Validating user with Redis...")
	rdb := redis.NewClient(&redis.Options{
		Addr:     config.Redis.Address,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})
	defer rdb.Close()

	ctx := context.Background()
	val, err := rdb.Get(ctx, username).Result()
	if err != nil {
		if err == redis.Nil {
			fmt.Println("User not found in Redis")
		} else {
			fmt.Println("Error querying Redis:", err)
		}
		return false
	}

	fmt.Println("User found in Redis:", val)
	return true
}

func main() {
	err := loadConfig("config.yaml")
	if err != nil {
		fmt.Println("Error loading configuration:", err)
		os.Exit(1)
	}

	listener, err := net.Listen("tcp", ":3306")
	if err != nil {
		fmt.Println("Error starting proxy:", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Println("MySQL Proxy listening on port 3306...")

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go handleClient(clientConn)
	}
}

func loadConfig(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, &config)
}

func handleClient(clientConn net.Conn) {
	defer clientConn.Close()

	username := extractUsername(clientConn)
	if username == "" {
		fmt.Println("Failed to extract username")
		return
	}

	var validator UserValidator
	switch config.AuthMethod {
	case "ldap":
		validator = &LDAPValidator{}
	case "redis":
		validator = &RedisValidator{}
	default:
		fmt.Println("Invalid authentication method in configuration")
		return
	}

	if !validator.Validate(username) {
		fmt.Println("User validation failed")
		return
	}

	mysqlServer := "127.0.0.1:3307"
	serverConn, err := net.Dial("tcp", mysqlServer)
	if err != nil {
		fmt.Println("Error connecting to MySQL server:", err)
		return
	}
	defer serverConn.Close()

	go forwardData(clientConn, serverConn)
	forwardData(serverConn, clientConn)
}

func extractUsername(conn net.Conn) string {
	reader := bufio.NewReader(conn)
	// Read the MySQL handshake packet and extract the username
	// This is a simplified example; you may need to parse the MySQL protocol properly
	data, err := reader.Peek(1024) // Adjust buffer size as needed
	if err != nil {
		fmt.Println("Error reading handshake packet:", err)
		return ""
	}

	// Parse the username from the handshake packet
	// (This is a placeholder; replace with actual MySQL protocol parsing logic)
	username := "user" // Replace with extracted username
	return username
}

func forwardData(src net.Conn, dest net.Conn) {
	reader := bufio.NewReader(src)
	writer := bufio.NewWriter(dest)

	for {
		data, err := reader.ReadBytes('\n')
		if err != nil {
			fmt.Println("Error reading data:", err)
			return
		}

		_, err = writer.Write(data)
		if err != nil {
			fmt.Println("Error writing data:", err)
			return
		}
		writer.Flush()
	}
}