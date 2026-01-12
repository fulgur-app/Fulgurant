.PHONY: help build start stop restart logs clean backup

help: ## Show this help message
	@echo "Fulgurant Docker Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the Docker image
	docker-compose build

start: ## Start the container
	docker-compose up -d
	@echo "Fulgurant is starting..."
	@echo "Access it at: http://localhost:3000"
	@echo "First-time setup: http://localhost:3000/setup"

stop: ## Stop the container
	docker-compose down

restart: ## Restart the container
	docker-compose restart

logs: ## View container logs (follow mode)
	docker-compose logs -f

logs-tail: ## View last 100 lines of logs
	docker-compose logs --tail 100

status: ## Show container status
	docker-compose ps

shell: ## Open shell in container
	docker-compose exec fulgurant sh

clean: ## Stop and remove container, volumes, and images
	docker-compose down -v
	docker rmi fulgurant:latest || true

rebuild: ## Rebuild from scratch (no cache)
	docker-compose build --no-cache
	docker-compose up -d

backup: ## Create backup of data directory
	@mkdir -p backups
	@tar -czf backups/fulgurant-backup-$$(date +%Y%m%d-%H%M%S).tar.gz data/
	@echo "Backup created in backups/"

update: ## Pull latest changes and rebuild
	git pull
	docker-compose build
	docker-compose up -d

dev: ## Start in development mode with live logs
	docker-compose up

health: ## Check container health
	@docker inspect --format='{{.State.Health.Status}}' fulgurant || echo "No health status available"

size: ## Show Docker image size
	@docker images fulgurant --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"
