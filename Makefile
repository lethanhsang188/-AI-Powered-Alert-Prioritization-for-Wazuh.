.PHONY: up down logs test clean

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f pipeline

test:
	pytest -q

clean:
	docker compose down -v
	find . -type d -name __pycache__ -exec rm -r {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -f state/cursor.json

