build: sso_cognito_client_secret/requirements.txt sso_random_secret/requirements.txt sso_pre_token_generation/requirements.txt
	sam build --config-env sso-part-1
	sam build --config-env sso-part-2

uv.lock: pyproject.toml
	uv lock

sso_cognito_client_secret/requirements.txt: uv.lock
	uv pip compile pyproject.toml -o $@

sso_random_secret/requirements.txt: uv.lock
	uv pip compile pyproject.toml -o $@

sso_pre_token_generation/requirements.txt: uv.lock
	uv pip compile pyproject.toml -o $@


test-random-secret:
	uv run python sso_random_secret/app.py events/traefik-sso_random-secret_event-create.json
	uv run python sso_random_secret/app.py events/traefik-sso_random-secret_event-update.json
	uv run python sso_random_secret/app.py events/traefik-sso_random-secret_event-delete.json

test-client-secret:
	uv run python sso_cognito_client_secret/app.py events/traefik-sso_cognito-client-secret_event-create.json
	uv run python sso_cognito_client_secret/app.py events/traefik-sso_cognito-client-secret_event-update.json
	uv run python sso_cognito_client_secret/app.py events/traefik-sso_cognito-client-secret_event-delete.json

