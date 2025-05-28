package cleanup

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/repository"
	"log"
	"sync"
	"time"
)

type CleanupJob struct {
	store        *repository.Store
	config       domain.CleanupConfiguration
	stopChan     chan struct{}
	doneChan     chan struct{}
	inCleanup    bool
	cleanupMutex sync.Mutex
	stopped      bool
}

func NewCleanupJob(store *repository.Store, config domain.CleanupConfiguration) *CleanupJob {
	return &CleanupJob{
		store:     store,
		config:    config,
		stopChan:  make(chan struct{}),
		doneChan:  make(chan struct{}),
		inCleanup: false,
		stopped:   false,
	}
}

func (j *CleanupJob) Start() {
	go j.run()
}

func (j *CleanupJob) Stop() {
	j.cleanupMutex.Lock()
	j.stopped = true
	j.cleanupMutex.Unlock()
	close(j.stopChan)
	<-j.doneChan // Wait for the cleanup goroutine to finish
}

func (j *CleanupJob) run() {
	ticker := time.NewTicker(j.config.CleanupInterval)
	defer ticker.Stop()
	defer close(j.doneChan)

	for {
		select {
		case <-j.stopChan:
			return
		case <-ticker.C:
			j.cleanupMutex.Lock()
			if !j.stopped {
				j.inCleanup = true
				if err := j.cleanup(); err != nil {
					if err.Error() != "sql: database is closed" {
						log.Printf("Error during cleanup: %v", err)
					}
				}
				j.inCleanup = false
			}
			j.cleanupMutex.Unlock()
		}
	}
}

func (j *CleanupJob) cleanup() error {
	// Delete expired verification tokens
	if err := j.store.DeleteExpiredVerificationTokens(); err != nil {
		return err
	}

	// Delete unverified users that are older than the max age
	if err := j.store.DeleteUnverifiedUsers(j.config.UnverifiedUserMaxAge); err != nil {
		return err
	}

	// Clean up expired email tracking records
	if err := j.store.CleanupExpiredEmailTracking(); err != nil {
		return err
	}

	return nil
}
