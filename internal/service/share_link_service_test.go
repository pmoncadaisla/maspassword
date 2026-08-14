package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/masorange/maspassword/internal/models"
	"github.com/masorange/maspassword/internal/repository"
	"github.com/masorange/maspassword/pkg/dto"
)

// --- In-memory fakes (hermetic, no DB) ---

type fakeShareLinkRepo struct {
	links map[uuid.UUID]*models.ShareLink
}

func newFakeShareLinkRepo() *fakeShareLinkRepo {
	return &fakeShareLinkRepo{links: make(map[uuid.UUID]*models.ShareLink)}
}

func (f *fakeShareLinkRepo) Create(_ context.Context, link *models.ShareLink) error {
	link.ID = uuid.New()
	link.CreatedAt = time.Now()
	cp := *link
	f.links[link.ID] = &cp
	return nil
}

func (f *fakeShareLinkRepo) GetByID(_ context.Context, id uuid.UUID) (*models.ShareLink, error) {
	l, ok := f.links[id]
	if !ok {
		return nil, repository.ErrShareLinkNotFound
	}
	cp := *l
	return &cp, nil
}

func (f *fakeShareLinkRepo) ListByItem(_ context.Context, itemID uuid.UUID) ([]models.ShareLink, error) {
	var out []models.ShareLink
	for _, l := range f.links {
		if l.ItemID == itemID {
			out = append(out, *l)
		}
	}
	return out, nil
}

// Redeem mirrors the SQL semantics: single-use, atomic, expiry-aware.
func (f *fakeShareLinkRepo) Redeem(_ context.Context, id uuid.UUID) (string, error) {
	l, ok := f.links[id]
	if !ok {
		return "", repository.ErrShareLinkNotFound
	}
	if l.RedeemedAt != nil || !l.ExpiresAt.After(time.Now()) {
		return "", repository.ErrShareLinkGone
	}
	now := time.Now()
	l.RedeemedAt = &now
	return l.PayloadEncrypted, nil
}

func (f *fakeShareLinkRepo) GetStatus(_ context.Context, id uuid.UUID) (bool, error) {
	l, ok := f.links[id]
	if !ok {
		return false, repository.ErrShareLinkNotFound
	}
	return l.RedeemedAt == nil && l.ExpiresAt.After(time.Now()), nil
}

func (f *fakeShareLinkRepo) Delete(_ context.Context, id uuid.UUID) error {
	if _, ok := f.links[id]; !ok {
		return repository.ErrShareLinkNotFound
	}
	delete(f.links, id)
	return nil
}

type fakeTeamRepo struct {
	members map[string]*models.TeamMember
}

func newFakeTeamRepo() *fakeTeamRepo {
	return &fakeTeamRepo{members: make(map[string]*models.TeamMember)}
}

func tmKey(teamID, userID uuid.UUID) string {
	return teamID.String() + ":" + userID.String()
}

func (f *fakeTeamRepo) setMember(teamID, userID uuid.UUID, role string) {
	f.members[tmKey(teamID, userID)] = &models.TeamMember{TeamID: teamID, UserID: userID, Role: role}
}

func (f *fakeTeamRepo) Create(context.Context, *models.Team) error { return nil }
func (f *fakeTeamRepo) GetByID(context.Context, uuid.UUID) (*models.Team, error) {
	return nil, repository.ErrTeamNotFound
}
func (f *fakeTeamRepo) ListByUser(context.Context, uuid.UUID) ([]models.Team, error) {
	return nil, nil
}
func (f *fakeTeamRepo) AddMember(context.Context, *models.TeamMember) error      { return nil }
func (f *fakeTeamRepo) RemoveMember(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (f *fakeTeamRepo) GetMember(_ context.Context, teamID, userID uuid.UUID) (*models.TeamMember, error) {
	m, ok := f.members[tmKey(teamID, userID)]
	if !ok {
		return nil, repository.ErrMemberNotFound
	}
	cp := *m
	return &cp, nil
}
func (f *fakeTeamRepo) UpdateMemberRole(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}
func (f *fakeTeamRepo) ListMembers(context.Context, uuid.UUID) ([]repository.TeamMemberWithEmail, error) {
	return nil, nil
}
func (f *fakeTeamRepo) IsMember(_ context.Context, teamID, userID uuid.UUID) (bool, error) {
	_, ok := f.members[tmKey(teamID, userID)]
	return ok, nil
}
func (f *fakeTeamRepo) ListMemberIDs(context.Context, uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}
func (f *fakeTeamRepo) GetMembersWithoutVaultKeys(context.Context, uuid.UUID) ([]repository.MemberPendingVaultKey, error) {
	return nil, nil
}

// fixture: a personal vault (owner) with one item, plus a team vault with an
// admin and a plain member.
type shareLinkFixture struct {
	svc         ShareLinkService
	linkRepo    *fakeShareLinkRepo
	vaultRepo   *fakeVaultRepo
	itemRepo    *fakeItemRepo
	teamRepo    *fakeTeamRepo
	owner       uuid.UUID
	vaultID     uuid.UUID
	itemID      uuid.UUID
	teamID      uuid.UUID
	teamAdmin   uuid.UUID
	teamMember  uuid.UUID
	teamVaultID uuid.UUID
	teamItemID  uuid.UUID
}

func newShareLinkFixture(t *testing.T) *shareLinkFixture {
	t.Helper()
	linkRepo := newFakeShareLinkRepo()
	vaultRepo := newFakeVaultRepo()
	itemRepo := newFakeItemRepo()
	teamRepo := newFakeTeamRepo()

	fx := &shareLinkFixture{
		linkRepo:    linkRepo,
		vaultRepo:   vaultRepo,
		itemRepo:    itemRepo,
		teamRepo:    teamRepo,
		owner:       uuid.New(),
		vaultID:     uuid.New(),
		itemID:      uuid.New(),
		teamID:      uuid.New(),
		teamAdmin:   uuid.New(),
		teamMember:  uuid.New(),
		teamVaultID: uuid.New(),
		teamItemID:  uuid.New(),
	}

	// Personal vault + item.
	vaultRepo.vaults[fx.vaultID] = &models.Vault{ID: fx.vaultID, OwnerID: fx.owner}
	itemRepo.items[fx.itemID] = &models.Item{ID: fx.itemID, VaultID: fx.vaultID, DataEncrypted: "cipher", Version: 1}

	// Team vault (owned by the plain member, associated with the team) + item.
	vaultRepo.vaults[fx.teamVaultID] = &models.Vault{ID: fx.teamVaultID, OwnerID: fx.teamMember, TeamID: &fx.teamID}
	vaultRepo.teamShares[fx.teamVaultID] = []repository.VaultTeamShare{{TeamID: fx.teamID}}
	itemRepo.items[fx.teamItemID] = &models.Item{ID: fx.teamItemID, VaultID: fx.teamVaultID, DataEncrypted: "team-cipher", Version: 1}
	teamRepo.setMember(fx.teamID, fx.teamAdmin, "admin")
	teamRepo.setMember(fx.teamID, fx.teamMember, "member")

	fx.svc = NewShareLinkService(linkRepo, vaultRepo, itemRepo, teamRepo)
	return fx
}

func createReq() dto.CreateShareLinkRequest {
	return dto.CreateShareLinkRequest{PayloadEncrypted: "opaque-payload", ExpiresInHours: 24}
}

// --- Authorization (role-based) ---

func TestShareLink_Create_PersonalVault_OwnerAllowed(t *testing.T) {
	fx := newShareLinkFixture(t)

	link, err := fx.svc.Create(context.Background(), fx.owner, fx.vaultID, fx.itemID, createReq())
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if link.ID == uuid.Nil || link.CreatedBy != fx.owner {
		t.Fatalf("unexpected link: %+v", link)
	}
	wantExpiry := time.Now().Add(24 * time.Hour)
	if link.ExpiresAt.Before(wantExpiry.Add(-time.Minute)) || link.ExpiresAt.After(wantExpiry.Add(time.Minute)) {
		t.Fatalf("expiry not ~24h from now: %v", link.ExpiresAt)
	}
}

func TestShareLink_Create_PersonalVault_NonOwnerForbidden(t *testing.T) {
	fx := newShareLinkFixture(t)
	stranger := uuid.New()

	_, err := fx.svc.Create(context.Background(), stranger, fx.vaultID, fx.itemID, createReq())
	if !errors.Is(err, ErrShareLinkForbidden) {
		t.Fatalf("expected ErrShareLinkForbidden, got %v", err)
	}
}

func TestShareLink_Create_TeamVault_AdminAllowed(t *testing.T) {
	fx := newShareLinkFixture(t)

	link, err := fx.svc.Create(context.Background(), fx.teamAdmin, fx.teamVaultID, fx.teamItemID, createReq())
	if err != nil {
		t.Fatalf("expected team admin to create link, got %v", err)
	}
	if link.CreatedBy != fx.teamAdmin {
		t.Fatalf("unexpected creator: %v", link.CreatedBy)
	}
}

func TestShareLink_Create_TeamVault_MemberForbidden(t *testing.T) {
	fx := newShareLinkFixture(t)

	// Even the vault OWNER is forbidden on a team vault when not an admin.
	_, err := fx.svc.Create(context.Background(), fx.teamMember, fx.teamVaultID, fx.teamItemID, createReq())
	if !errors.Is(err, ErrShareLinkForbidden) {
		t.Fatalf("expected ErrShareLinkForbidden for non-admin member, got %v", err)
	}
}

func TestShareLink_Create_ItemInDifferentVault(t *testing.T) {
	fx := newShareLinkFixture(t)

	_, err := fx.svc.Create(context.Background(), fx.owner, fx.vaultID, fx.teamItemID, createReq())
	if !errors.Is(err, repository.ErrItemNotFound) {
		t.Fatalf("expected ErrItemNotFound, got %v", err)
	}
}

func TestShareLink_Create_Validation(t *testing.T) {
	fx := newShareLinkFixture(t)

	req := createReq()
	req.PayloadEncrypted = strings.Repeat("x", (1<<20)+1)
	if _, err := fx.svc.Create(context.Background(), fx.owner, fx.vaultID, fx.itemID, req); !errors.Is(err, ErrSharePayloadTooLarge) {
		t.Fatalf("expected ErrSharePayloadTooLarge, got %v", err)
	}

	req = createReq()
	req.ExpiresInHours = 0
	if _, err := fx.svc.Create(context.Background(), fx.owner, fx.vaultID, fx.itemID, req); !errors.Is(err, ErrShareExpiryInvalid) {
		t.Fatalf("expected ErrShareExpiryInvalid for 0h, got %v", err)
	}

	req.ExpiresInHours = 73
	if _, err := fx.svc.Create(context.Background(), fx.owner, fx.vaultID, fx.itemID, req); !errors.Is(err, ErrShareExpiryInvalid) {
		t.Fatalf("expected ErrShareExpiryInvalid for 73h, got %v", err)
	}
}

func TestShareLink_List_RequiresManageRole(t *testing.T) {
	fx := newShareLinkFixture(t)
	if _, err := fx.svc.Create(context.Background(), fx.owner, fx.vaultID, fx.itemID, createReq()); err != nil {
		t.Fatalf("creating link: %v", err)
	}

	links, err := fx.svc.List(context.Background(), fx.owner, fx.vaultID, fx.itemID)
	if err != nil || len(links) != 1 {
		t.Fatalf("owner list failed: %v (%d links)", err, len(links))
	}

	if _, err := fx.svc.List(context.Background(), uuid.New(), fx.vaultID, fx.itemID); !errors.Is(err, ErrShareLinkForbidden) {
		t.Fatalf("expected ErrShareLinkForbidden for stranger, got %v", err)
	}
}

// --- Single-use redeem semantics ---

func TestShareLink_Redeem_SingleUse(t *testing.T) {
	fx := newShareLinkFixture(t)
	link, err := fx.svc.Create(context.Background(), fx.owner, fx.vaultID, fx.itemID, createReq())
	if err != nil {
		t.Fatalf("creating link: %v", err)
	}

	if status, err := fx.svc.Status(context.Background(), link.ID); err != nil || status != "available" {
		t.Fatalf("expected available before redeem, got %q (%v)", status, err)
	}

	payload, err := fx.svc.Redeem(context.Background(), link.ID)
	if err != nil {
		t.Fatalf("first redeem must succeed, got %v", err)
	}
	if payload != "opaque-payload" {
		t.Fatalf("unexpected payload %q", payload)
	}

	// Second redeem must fail: single use.
	if _, err := fx.svc.Redeem(context.Background(), link.ID); !errors.Is(err, repository.ErrShareLinkGone) {
		t.Fatalf("expected ErrShareLinkGone on second redeem, got %v", err)
	}

	if status, err := fx.svc.Status(context.Background(), link.ID); err != nil || status != "gone" {
		t.Fatalf("expected gone after redeem, got %q (%v)", status, err)
	}
}

func TestShareLink_Redeem_Expired(t *testing.T) {
	fx := newShareLinkFixture(t)
	link, err := fx.svc.Create(context.Background(), fx.owner, fx.vaultID, fx.itemID, createReq())
	if err != nil {
		t.Fatalf("creating link: %v", err)
	}
	// Force expiry in the stored link.
	fx.linkRepo.links[link.ID].ExpiresAt = time.Now().Add(-time.Minute)

	if _, err := fx.svc.Redeem(context.Background(), link.ID); !errors.Is(err, repository.ErrShareLinkGone) {
		t.Fatalf("expected ErrShareLinkGone for expired link, got %v", err)
	}
	if status, _ := fx.svc.Status(context.Background(), link.ID); status != "gone" {
		t.Fatalf("expected gone status for expired link, got %q", status)
	}
}

func TestShareLink_Redeem_NeverExisted(t *testing.T) {
	fx := newShareLinkFixture(t)

	if _, err := fx.svc.Redeem(context.Background(), uuid.New()); !errors.Is(err, repository.ErrShareLinkNotFound) {
		t.Fatalf("expected ErrShareLinkNotFound, got %v", err)
	}
	if _, err := fx.svc.Status(context.Background(), uuid.New()); !errors.Is(err, repository.ErrShareLinkNotFound) {
		t.Fatalf("expected ErrShareLinkNotFound from status, got %v", err)
	}
}

// --- Revocation authorization ---

func TestShareLink_Delete_CreatorAllowed(t *testing.T) {
	fx := newShareLinkFixture(t)
	link, _ := fx.svc.Create(context.Background(), fx.owner, fx.vaultID, fx.itemID, createReq())

	if err := fx.svc.Delete(context.Background(), fx.owner, link.ID); err != nil {
		t.Fatalf("creator must be able to revoke, got %v", err)
	}
	if _, ok := fx.linkRepo.links[link.ID]; ok {
		t.Fatal("link should be deleted")
	}
}

func TestShareLink_Delete_TeamAdminAllowed(t *testing.T) {
	fx := newShareLinkFixture(t)
	link, _ := fx.svc.Create(context.Background(), fx.teamAdmin, fx.teamVaultID, fx.teamItemID, createReq())

	// A different admin (not the creator) may revoke via the manage policy.
	otherAdmin := uuid.New()
	fx.teamRepo.setMember(fx.teamID, otherAdmin, "admin")
	if err := fx.svc.Delete(context.Background(), otherAdmin, link.ID); err != nil {
		t.Fatalf("team admin must be able to revoke, got %v", err)
	}
}

func TestShareLink_Delete_StrangerForbidden(t *testing.T) {
	fx := newShareLinkFixture(t)
	link, _ := fx.svc.Create(context.Background(), fx.owner, fx.vaultID, fx.itemID, createReq())

	if err := fx.svc.Delete(context.Background(), uuid.New(), link.ID); !errors.Is(err, ErrShareLinkForbidden) {
		t.Fatalf("expected ErrShareLinkForbidden, got %v", err)
	}
	if _, ok := fx.linkRepo.links[link.ID]; !ok {
		t.Fatal("link must NOT be deleted by a stranger")
	}
}

func TestShareLink_Delete_NotFound(t *testing.T) {
	fx := newShareLinkFixture(t)

	if err := fx.svc.Delete(context.Background(), fx.owner, uuid.New()); !errors.Is(err, repository.ErrShareLinkNotFound) {
		t.Fatalf("expected ErrShareLinkNotFound, got %v", err)
	}
}
