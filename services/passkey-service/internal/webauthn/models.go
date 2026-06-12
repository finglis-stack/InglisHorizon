package webauthn

import (
	"context"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PasskeyUser struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *PasskeyUser) WebAuthnID() []byte {
	return u.ID
}

func (u *PasskeyUser) WebAuthnName() string {
	return u.Name
}

func (u *PasskeyUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *PasskeyUser) WebAuthnIcon() string {
	return ""
}

func (u *PasskeyUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// LoadUserCredentials loads all registered WebAuthn credentials for a given account.
func LoadUserCredentials(ctx context.Context, pool *pgxpool.Pool, accountID string) ([]webauthn.Credential, error) {
	rows, err := pool.Query(ctx, "SELECT credential_id, public_key, attestation_type, aaguid, sign_counter FROM account_passkeys WHERE account_id = $1", accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to select account passkeys: %w", err)
	}
	defer rows.Close()

	var credentials []webauthn.Credential
	for rows.Next() {
		var cred webauthn.Credential
		var aaguid []byte
		var signCounter int64

		err := rows.Scan(
			&cred.ID,
			&cred.PublicKey,
			&cred.AttestationType,
			&aaguid,
			&signCounter,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}

		cred.Authenticator.AAGUID = aaguid
		cred.Authenticator.SignCount = uint32(signCounter)
		credentials = append(credentials, cred)
	}

	return credentials, nil
}

// SaveUserCredential saves a newly registered WebAuthn credential for an account.
func SaveUserCredential(ctx context.Context, pool *pgxpool.Pool, accountID string, cred *webauthn.Credential) error {
	query := `
		INSERT INTO account_passkeys (account_id, credential_id, public_key, attestation_type, aaguid, sign_counter)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := pool.Exec(ctx, query,
		accountID,
		cred.ID,
		cred.PublicKey,
		cred.AttestationType,
		cred.Authenticator.AAGUID,
		int64(cred.Authenticator.SignCount),
	)
	if err != nil {
		return fmt.Errorf("failed to insert user credential: %w", err)
	}
	return nil
}
