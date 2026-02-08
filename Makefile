# Makefile for AWS Security Notification System

.PHONY: help package upload deploy clean logs test aws-test validate update setup

help:
	@echo "AWS Security Notification System - v3.0.0"
	@echo ""
	@echo "Commands:"
	@echo "  make package    - Create Lambda deployment package"
	@echo "  make upload     - Upload package to S3 (set BUCKET variable)"
	@echo "  make deploy     - Deploy CloudFormation stack (set BUCKET and WEBHOOK)"
	@echo "  make logs       - Tail Lambda logs"
	@echo "  make test       - Run unit tests"
	@echo "  make aws-test   - Trigger AWS test event"
	@echo "  make clean      - Clean all build artifacts"
	@echo "  make validate   - Validate CloudFormation template"
	@echo "  make update     - Update Lambda code (set BUCKET)"
	@echo "  make setup      - Complete setup (package + upload + deploy)"

package:
	@echo "Creating deployment package..."
	@echo "Cleaning old artifacts..."
	rm -rf ./security_notifier ./boto3 ./botocore ./requests ./urllib3 ./certifi ./charset_normalizer ./idna ./dateutil ./jmespath ./s3transfer function.zip 2>/dev/null || true
	@echo "Copying source code..."
	cp -r src/security_notifier .
	@echo "Installing dependencies..."
	pip install -r requirements-lambda.txt -t . --upgrade --quiet 2>/dev/null || pip install boto3 requests -t . --upgrade --quiet
	@echo "Creating deployment package..."
	zip -r function.zip security_notifier/ -x "*.pyc" -x "*__pycache__*" -q
	@echo "Adding dependencies..."
	zip -r function.zip boto3/ botocore/ requests/ urllib3/ certifi/ charset_normalizer/ idna/ dateutil/ jmespath/ s3transfer/ six.py -q 2>/dev/null || true
	@echo "Cleaning temporary files..."
	rm -rf ./security_notifier ./boto3 ./botocore ./requests ./urllib3 ./certifi ./charset_normalizer ./idna ./dateutil ./jmespath ./s3transfer
	@echo "✓ Package created: function.zip"

upload:
ifndef BUCKET
	$(error BUCKET is required. Usage: make upload BUCKET=my-bucket)
endif
	@echo "Uploading to S3..."
	aws s3 cp function.zip s3://$(BUCKET)/
	@echo "Uploaded to s3://$(BUCKET)/function.zip"

deploy:
ifndef BUCKET
	$(error BUCKET is required)
endif
ifndef WEBHOOK
	$(error WEBHOOK is required. Usage: make deploy BUCKET=my-bucket WEBHOOK=https://hooks.slack.com/...)
endif
	@echo "Deploying CloudFormation stack..."
	aws cloudformation deploy \
		--template-file template.yaml \
		--stack-name security-notifications \
		--capabilities CAPABILITY_IAM \
		--parameter-overrides \
		  LambdaCodeBucket=$(BUCKET) \
		  SlackWebhookUrl=$(WEBHOOK) \
		  AccountName=$(or $(ACCOUNT),Production)
	@echo "Deployment complete!"

logs:
	@echo "Tailing Lambda logs (Ctrl+C to stop)..."
	aws logs tail /aws/lambda/security-notifications-notification-lambda --follow

test:
	@echo "Running unit tests..."
	PYTHONPATH=src python3 -m pytest tests/ -v

aws-test:
	@echo "Triggering AWS test event..."
	aws iam create-user --user-name test-security-alert-$(shell date +%s) || true
	@echo "Check Slack for notification!"

clean:
	@echo "Cleaning artifacts..."
	rm -f function.zip
	rm -rf security_notifier/ boto3/ botocore/ requests/ urllib3/ certifi/ charset_normalizer/ idna/ dateutil/ jmespath/ s3transfer/ six.py
	rm -rf venv/ .pytest_cache/ __pycache__/ */__pycache__/ */*/__pycache__/
	find . -name "*.pyc" -delete
	@echo "✓ Clean complete"

validate:
	@echo "Validating CloudFormation template..."
	aws cloudformation validate-template --template-body file://template.yaml
	@echo "Template is valid!"

update:
	@echo "Updating Lambda code..."
	make package
	make upload BUCKET=$(BUCKET)
	aws lambda update-function-code \
		--function-name security-notifications-notification-lambda \
		--s3-bucket $(BUCKET) \
		--s3-key function.zip
	@echo "Lambda updated!"

# Quick setup (all in one)
setup: package
ifndef BUCKET
	$(error BUCKET is required)
endif
ifndef WEBHOOK
	$(error WEBHOOK is required)
endif
	make upload BUCKET=$(BUCKET)
	make deploy BUCKET=$(BUCKET) WEBHOOK=$(WEBHOOK)
	@echo ""
	@echo "Setup complete!"
	@echo "Run 'make test' to trigger a test event"

