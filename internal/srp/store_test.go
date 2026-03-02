package srp

import (
	"testing"
	"time"
)

func TestStore_SetAndGet(t *testing.T) {
	store := NewStore(5 * time.Minute)

	store.Set("session-1", []byte("server-data"), "user-123")

	data, userID, ok := store.Get("session-1")
	if !ok {
		t.Fatal("expected session to exist")
	}
	if string(data) != "server-data" {
		t.Errorf("expected server-data, got %s", string(data))
	}
	if userID != "user-123" {
		t.Errorf("expected user-123, got %s", userID)
	}
}

func TestStore_GetNonExistent(t *testing.T) {
	store := NewStore(5 * time.Minute)

	_, _, ok := store.Get("non-existent")
	if ok {
		t.Fatal("expected session to not exist")
	}
}

func TestStore_Expiry(t *testing.T) {
	store := NewStore(50 * time.Millisecond)

	store.Set("session-1", []byte("data"), "user-1")
	time.Sleep(100 * time.Millisecond)

	_, _, ok := store.Get("session-1")
	if ok {
		t.Fatal("expected session to have expired")
	}
}

func TestStore_Delete(t *testing.T) {
	store := NewStore(5 * time.Minute)

	store.Set("session-1", []byte("data"), "user-1")
	store.Delete("session-1")

	_, _, ok := store.Get("session-1")
	if ok {
		t.Fatal("expected session to be deleted")
	}
}
