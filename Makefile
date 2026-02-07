# Makefile for AWS Security Notification System

.PHONY: help package upload deploy clean logs test validate update setup

help:
	@echo "AWS Security Notification System"
	@echo ""
	@echo "Commands:"
	@echo "  make package    - Create Lambda deployment package"
	@echo "  make upload     - Upload package to S3 (set BUCKET variable)"
	@echo "  make deploy     - Deploy CloudFormation stack (set BUCKET and WEBHOOK)"
	@echo "  make logs       - Tail Lambda logs"
	@echo "  make test       - Run unit tests"
	@echo "  make clean      - Clean build artifacts"

package:
	@echo "Creating deployment package..."
	rm -rf build/
	mkdir -p build/
	pip install -r requirements-lambda.txt -t build/ --quiet
	cp -r src/security_notifier build/
	cd build && zip -r ../function.zip . -x '__pycache__/*' '*.pyc' '*.dist-info/*'
	@echo "Package created: function.zip"

test:
	python -m pytest tests/ -v

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

clean:
	@echo "Cleaning artifacts..."
	rm -rf function.zip build/
	@echo "Clean complete"

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
	@echo "Run 'make test' to run unit tests"
