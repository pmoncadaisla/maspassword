package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/masorange/maspassword/internal/models"
	"github.com/masorange/maspassword/internal/repository"
)

// The fakes (fakeVaultRepo, fakeVaultKeyRepo, fakeTeamRepo) live in the other
// *_test.go files of this package.

func TestVaultServiceDelete(t *testing.T) {
	owner := uuid.New()
	stranger := uuid.New()
	sharee := uuid.New()
	teamAdmin := uuid.New()
	teamMember := uuid.New()
	teamID := uuid.New()

	setup := func() (VaultService, *fakeVaultRepo, uuid.UUID, uuid.UUID) {
		vaultRepo := newFakeVaultRepo()
		vaultKeyRepo := newFakeVaultKeyRepo()
		teamRepo := newFakeTeamRepo()
		teamRepo.setMember(teamID, teamAdmin, "admin")
		teamRepo.setMember(teamID, teamMember, "member")

		personal := &models.Vault{OwnerID: owner, NameEncrypted: "enc"}
		if err := vaultRepo.Create(context.Background(), personal); err != nil {
			t.Fatal(err)
		}
		// The sharee holds a vault key (shared personal vault): may read, but
		// must never be able to delete.
		_ = vaultKeyRepo.Create(context.Background(), &models.VaultKey{
			VaultID: personal.ID, UserID: sharee, EncryptedVaultKey: "wrapped",
		})

		teamVault := &models.Vault{OwnerID: owner, NameEncrypted: "enc", TeamID: &teamID}
		if err := vaultRepo.Create(context.Background(), teamVault); err != nil {
			t.Fatal(err)
		}

		svc := NewVaultService(vaultRepo, vaultKeyRepo, teamRepo)
		return svc, vaultRepo, personal.ID, teamVault.ID
	}

	t.Run("owner deletes personal vault", func(t *testing.T) {
		svc, repo, personalID, _ := setup()
		if err := svc.Delete(context.Background(), owner, personalID); err != nil {
			t.Fatalf("owner delete = %v, want nil", err)
		}
		if _, ok := repo.vaults[personalID]; ok {
			t.Error("vault still present after delete")
		}
	})

	t.Run("sharee cannot delete a personal vault", func(t *testing.T) {
		svc, repo, personalID, _ := setup()
		if err := svc.Delete(context.Background(), sharee, personalID); !errors.Is(err, ErrNoVaultAccess) {
			t.Fatalf("sharee delete = %v, want ErrNoVaultAccess", err)
		}
		if _, ok := repo.vaults[personalID]; !ok {
			t.Error("vault was deleted by a non-owner")
		}
	})

	t.Run("stranger cannot delete", func(t *testing.T) {
		svc, _, personalID, _ := setup()
		if err := svc.Delete(context.Background(), stranger, personalID); !errors.Is(err, ErrNoVaultAccess) {
			t.Fatalf("stranger delete = %v, want ErrNoVaultAccess", err)
		}
	})

	t.Run("team admin deletes team vault", func(t *testing.T) {
		svc, repo, _, teamVaultID := setup()
		if err := svc.Delete(context.Background(), teamAdmin, teamVaultID); err != nil {
			t.Fatalf("team admin delete = %v, want nil", err)
		}
		if _, ok := repo.vaults[teamVaultID]; ok {
			t.Error("team vault still present after admin delete")
		}
	})

	t.Run("plain team member cannot delete team vault", func(t *testing.T) {
		svc, _, _, teamVaultID := setup()
		if err := svc.Delete(context.Background(), teamMember, teamVaultID); !errors.Is(err, ErrNoVaultAccess) {
			t.Fatalf("member delete = %v, want ErrNoVaultAccess", err)
		}
	})

	t.Run("owner deletes team vault even without admin role", func(t *testing.T) {
		svc, repo, _, teamVaultID := setup()
		if err := svc.Delete(context.Background(), owner, teamVaultID); err != nil {
			t.Fatalf("owner delete of team vault = %v, want nil", err)
		}
		if _, ok := repo.vaults[teamVaultID]; ok {
			t.Error("team vault still present after owner delete")
		}
	})

	t.Run("missing vault reports not found", func(t *testing.T) {
		svc, _, _, _ := setup()
		if err := svc.Delete(context.Background(), owner, uuid.New()); !errors.Is(err, repository.ErrVaultNotFound) {
			t.Fatalf("delete missing = %v, want ErrVaultNotFound", err)
		}
	})
}
