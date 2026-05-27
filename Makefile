.PHONY: install test scan-risk scan-full baseline

install:
	pip install -r requirements.txt

test:
	python -m pytest tests/ -v

scan-risk:
	python main.py --mode risk --output iam-scan-report.json

scan-drift:
	python main.py --mode drift --baseline baselines/prod-baseline.json

scan-full:
	python main.py --mode full --baseline baselines/prod-baseline.json

baseline:
	python main.py --mode baseline --output baselines/prod-baseline.json
	@echo "Baseline generated. Commit alongside your Terraform changes:"
	@echo "  git add baselines/prod-baseline.json"
	@echo "  git commit -m 'chore(iam): update baseline after terraform apply'"

# No-AI variant for faster CI runs or environments without Gemini key
scan-no-ai:
	python main.py --mode full --baseline baselines/prod-baseline.json --no-ai
