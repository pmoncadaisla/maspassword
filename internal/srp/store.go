package srp

import (
	"sync"
	"time"
)

type srpSession struct {
	serverData []byte
	userID     string
	expiresAt  time.Time
}

type Store struct {
	sessions sync.Map
	ttl      time.Duration
}

func NewStore(ttl time.Duration) *Store {
	s := &Store{ttl: ttl}
	go s.cleanup()
	return s
}

func (s *Store) Set(sessionID string, serverData []byte, userID string) {
	s.sessions.Store(sessionID, &srpSession{
		serverData: serverData,
		userID:     userID,
		expiresAt:  time.Now().Add(s.ttl),
	})
}

func (s *Store) Get(sessionID string) (serverData []byte, userID string, ok bool) {
	val, exists := s.sessions.Load(sessionID)
	if !exists {
		return nil, "", false
	}
	sess := val.(*srpSession)
	if time.Now().After(sess.expiresAt) {
		s.sessions.Delete(sessionID)
		return nil, "", false
	}
	return sess.serverData, sess.userID, true
}

func (s *Store) Delete(sessionID string) {
	s.sessions.Delete(sessionID)
}

func (s *Store) cleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.sessions.Range(func(key, value any) bool {
			sess := value.(*srpSession)
			if now.After(sess.expiresAt) {
				s.sessions.Delete(key)
			}
			return true
		})
	}
}
