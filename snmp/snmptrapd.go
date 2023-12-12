package snmp

import (
	"fmt"
	"github.com/pkg/errors"
	"os"
	"strconv"
	"strings"
)

type Community struct {
	Name string
}

type AuthType int8

const (
	AuthSHA AuthType = iota
	AuthMD5
	AuthSHA128
	AuthSHA224
	AuthSHA256
	AuthSHA384
	AuthSHA512
)

func (a *AuthType) String() string {
	switch *a {
	case AuthMD5:
		return "MD5"
	case AuthSHA, AuthSHA128:
		return "SHA"
	case AuthSHA224:
		return "SHA-224"
	case AuthSHA256:
		return "SHA-256"
	case AuthSHA384:
		return "SHA-384"
	case AuthSHA512:
		return "SHA-512"
	default:
		return ""
	}
}

func (a *AuthType) UnmarshalText(text []byte) error {
	if a == nil {
		return errors.New("can't unmarshal a nil *AuthType")
	}
	switch strings.ToLower(string(text)) {
	case "md5":
		*a = AuthMD5
	case "sha", "sha-128":
		*a = AuthSHA
	case "sha-224":
		*a = AuthSHA224
	case "sha-256":
		*a = AuthSHA256
	case "sha-384":
		*a = AuthSHA384
	case "sha-512":
		*a = AuthSHA512
	default:
		return errors.Errorf("unsupported AuthType: %s", string(text))
	}
	return nil
}

type PrivacyProtocol int8

const (
	PrivAES PrivacyProtocol = iota
	PrivDES
	PrivAES128
	PrivAES192
	PrivAES256
)

func (p *PrivacyProtocol) String() string {
	switch *p {
	case PrivDES:
		return "DES"
	case PrivAES, PrivAES128:
		return "AES"
	case PrivAES192:
		return "AES-192"
	case PrivAES256:
		return "AES-256"
	default:
		return ""
	}
}

func (p *PrivacyProtocol) UnmarshalText(text []byte) error {
	if p == nil {
		return errors.New("can't unmarshal a nil *PrivacyProtocol")
	}
	switch strings.ToLower(string(text)) {
	case "des":
		*p = PrivDES
	case "aes", "aes-128":
		*p = PrivAES
	case "aes-192":
		*p = PrivAES192
	case "aes-256":
		*p = PrivAES256
	default:
		return errors.Errorf("unsupported PrivacyProtocol: %s", string(text))
	}
	return nil
}

type User struct {
	Username          string
	NoAuth            bool            `mapstructure:"no_auth"`
	RequirePrivacy    bool            `mapstructure:"require_privacy"`
	EngineID          string          `mapstructure:"engine_id"`
	AuthType          AuthType        `mapstructure:"auth_type"`
	AuthPassphrase    string          `mapstructure:"auth_passphrase"`
	PrivacyProtocol   PrivacyProtocol `mapstructure:"privacy_protocol"`
	PrivacyPassphrase string          `mapstructure:"privacy_passphrase"`
}

func (u User) SecurityLevel() string {
	if u.AuthPassphrase == "" {
		return "noAuthNoPriv"
	} else if u.PrivacyPassphrase == "" {
		return "authNoPriv"
	} else {
		return "authPriv"
	}
}

type AuthConfig struct {
	// Enable auth for v1 and v2. v3 still needs users to be defined
	Enable bool
	// Community for snmp V1 and V2
	Community []Community
	// User for snmp v3
	User []User
}

type Config struct {
	Auth             AuthConfig
	Listening        []string
	AdditionalConfig string `mapstructure:"additional_config"`
	MagicBegin       string `mapstructure:"magic_begin"`
	MagicEnd         string `mapstructure:"magic_end"`
	BufferSize       string `mapstructure:"buffer_size"`
}

func (c *Config) GetBufferSize() (int, error) {
	if len(c.BufferSize) == 0 {
		return 0, errors.New("empty buffer size")
	}
	multiplier := 1
	switch strings.ToLower(c.BufferSize)[len(c.BufferSize)-1] {
	case 'k':
		multiplier = 1e3
	case 'm':
		multiplier = 1e6
	case 'g':
		multiplier = 1e9
	case 't', 'p', 'e':
		return 0, errors.New("buffer_size too large, probably a mistake")
	}
	bufSize := c.BufferSize[:len(c.BufferSize)-1]
	bufInt, err := strconv.Atoi(bufSize)
	if err != nil {
		return 0, errors.Wrap(err, "failed reading buffer_size")
	}
	return bufInt * multiplier, nil
}

const (
	PidFilePath       = "/var/run/snmptrapd/snmptrapd.pid"
	DefaultBufferSize = 64000
)

func (c *Config) Serialize(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return errors.Wrapf(err, "failed opening file at %s", path)
	}
	defer f.Close()
	// snmptrapd flushes its stdout for every newline char, we add \n to make sure
	// it's flushed for every message
	trapConf := fmt.Sprintf(`pidFile %s
format1 %s%%a|%%b|%%t|%%T|%%W|%%N|%%P|%%w|%%q|%%v%s\n
format2 %s%%a|%%b|%%t|%%T|%%W|%%N|%%P|%%w|%%q|%%v%s\n
`, PidFilePath, c.MagicBegin, c.MagicEnd, c.MagicBegin, c.MagicEnd)
	if len(c.Listening) > 0 {
		trapConf += fmt.Sprintf("snmpTrapdAddr %s\n", strings.Join(c.Listening, " "))
	}
	if !c.Auth.Enable {
		trapConf += "disableAuthorization yes\n"
	} else {
		for _, comm := range c.Auth.Community {
			trapConf += fmt.Sprintf("authCommunity log %s\n", comm.Name)
		}
	}
	for _, user := range c.Auth.User {
		userStrBuilder := []string{"createUser"}
		if user.EngineID != "" {
			userStrBuilder = append(userStrBuilder, "-e", user.EngineID)
		}
		if user.Username == "" {
			return errors.Errorf("empty username")
		}
		userStrBuilder = append(userStrBuilder, user.Username, user.AuthType.String())
		if user.AuthPassphrase == "" {
			return errors.Errorf("empty auth_passphrase")
		}
		userStrBuilder = append(
			userStrBuilder,
			strconv.Quote(user.AuthPassphrase),
			user.PrivacyProtocol.String(),
		)
		if user.PrivacyPassphrase != "" {
			userStrBuilder = append(
				userStrBuilder,
				strconv.Quote(user.PrivacyPassphrase),
			)
		}
		trapConf += fmt.Sprintf("%s\n", strings.Join(userStrBuilder, " "))
		if user.RequirePrivacy {
			trapConf += fmt.Sprintf("authUser log %s priv\n", user.Username)
		} else if user.NoAuth {
			trapConf += fmt.Sprintf("authUser log %s noauth\n", user.Username)
		} else {
			trapConf += fmt.Sprintf("authUser log %s\n", user.Username)
		}
	}
	trapConf += c.AdditionalConfig
	if _, err = f.Write([]byte(trapConf)); err != nil {
		return errors.Wrapf(err, "failed writing file at %s", path)
	}
	return nil
}
