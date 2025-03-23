package cleanup

import (
	"aggregat4/openidprovider/internal/domain"
	"aggregat4/openidprovider/internal/repository"
	"log"
	"time"
)

type CleanupJob struct {
	store    *repository.Store
	config   domain.CleanupConfiguration
	stopChan chan struct{}
}

func NewCleanupJob(store *repository.Store, config domain.CleanupConfiguration) *CleanupJob {
	return &CleanupJob{
		store:    store,
		config:   config,
		stopChan: make(chan struct{}),
	}
}

func (j *CleanupJob) Start() {
	go j.run()
}

func (j *CleanupJob) Stop() {
	close(j.stopChan)
}

func (j *CleanupJob) run() {
	ticker := time.NewTicker(j.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-j.stopChan:
			return
		case <-ticker.C:
			if err := j.cleanup(); err != nil {
				log.Printf("Failed to run cleanup job: %v", err)
			}
		}
	}
}

func (j *CleanupJob) cleanup() error {
	// Delete expired verification tokens
	if err := j.store.DeleteExpiredVerificationTokens(); err != nil {
		return err
	}

	// Delete unverified users
	if err := j.store.DeleteUnverifiedUsers(j.config.UnverifiedUserMaxAge); err != nil {
		return err
	}

	return nil
}
