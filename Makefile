.PHONY: install test scan-risk scan-drift scan-full baseline scan-ai

install:
	python -m pip install -r requirements.txt

test:
	python -m pytest -q

scan-risk:
	python main.py --mode risk --no-ai --output iam-scan-report.json

scan-drift:
	python main.py --mode drift --baseline baselines/prod-baseline.json --no-ai

scan-full:
	python main.py --mode full --baseline baselines/prod-baseline.json --no-ai

baseline:
	python main.py --mode baseline --output baselines/prod-baseline.json --no-ai
	@echo "Baseline generated. Commit alongside your Terraform changes:"
	@echo "  git add baselines/prod-baseline.json"
	@echo "  git commit -m 'chore(iam): update baseline after terraform apply'"

# Optional AI explanation; requires GEMINI_API_KEY
scan-ai:
	python main.py --mode full --baseline baselines/prod-baseline.json --ai
