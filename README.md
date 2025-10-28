# AWS IAM Drift Detector

A Python tool that analyzes AWS IAM policies to detect risky permissions using AI-powered explanations. This tool identifies potential security vulnerabilities in your IAM policies and provides clear explanations using Google's Gemini AI.

## 🚀 Features

- **Automated IAM Policy Analysis**: Scans all customer-managed IAM policies in your AWS account
- **Risk Detection**: Identifies policies with overly broad permissions (wildcard actions/resources)
- **AI-Powered Explanations**: Uses Google Gemini AI to provide plain-English explanations of security risks
- **JSON Report Generation**: Creates detailed reports with policy ARNs, risky statements, and AI explanations
- **Easy Integration**: Simple Python script that can be integrated into CI/CD pipelines

## 🛠️ Setup

### Prerequisites

- Python 3.7+
- AWS CLI configured with appropriate credentials
- Google Cloud API key for Gemini AI

### Installation

1. Clone the repository:
```bash
git clone https://github.com/jibin006/AWS-IAM-Drift-Detector.git
cd AWS-IAM-Drift-Detector
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Configure AWS credentials:
```bash
aws configure
# OR set environment variables:
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=your_region
```

4. Set up Google Gemini API:
   - Get your API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
   - **⚠️ IMPORTANT**: Replace the hardcoded API key in `drift.py` with your own key
   - For production use, store the API key in environment variables:
   ```python
   import os
   genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
   ```

## 📖 Usage

### Basic Usage

Run the drift detector:
```bash
python drift.py
```

The tool will:
1. Scan all customer-managed IAM policies in your AWS account
2. Identify policies with risky permissions (wildcard actions/resources)
3. Generate AI explanations for each risky policy
4. Save results to `iam_risky_policies.json`

### Example Output

The tool generates a JSON report with the following structure:
```json
[
  {
    "PolicyName": "ExampleRiskyPolicy",
    "Arn": "arn:aws:iam::123456789012:policy/ExampleRiskyPolicy",
    "RiskyStatements": [
      {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }
    ],
    "AIExplanation": "This policy grants unrestricted access to all AWS services and resources, which poses significant security risks. An attacker with access to this policy could perform any action on any resource in your account."
  }
]
```

## 🔍 How It Works

### Detection Logic

The tool identifies risky IAM statements by checking for:
- **Wildcard Actions** (`"Action": "*"` or `"Action": ["*", ...]`)
- **Wildcard Resources** (`"Resource": "*"` or `"Resource": ["*", ...]`)

### AI Analysis

For each risky policy detected:
1. Policy details are sent to Google Gemini AI
2. AI provides a plain-English explanation of the security risks
3. Explanations are limited to 2-3 sentences for clarity

## Overall logic (big-picture)

Configure logging and clients (AWS and Gemini).

Scan all customer-managed IAM policies in the account.

Fetch the active JSON policy document for each policy.

Detect risky statements (currently only wildcard * actions or resources).

For risky policies, call an AI model to produce human-readable explanations and remediation suggestions.

Save all findings to a JSON report and print a summary.

## 🔧 Configuration

### Environment Variables

For production deployment, use environment variables:

```bash
export AWS_ACCESS_KEY_ID=your_aws_access_key
export AWS_SECRET_ACCESS_KEY=your_aws_secret_key  
export AWS_DEFAULT_REGION=us-west-2
export GEMINI_API_KEY=your_gemini_api_key
```

### Customizing Detection Rules

To modify the risk detection logic, edit the `risky_statements()` function in `drift.py`:

```python
def risky_statements(document):
    risky = []
    statements = document.get("Statement", [])
    
    # Add your custom risk detection logic here
    # Current logic checks for wildcard actions/resources
    
    return risky
```

## 📁 Project Structure

```
AWS-IAM-Drift-Detector/
├── drift.py              # Main detection script
├── requirements.txt      # Python dependencies
├── .gitignore           # Git ignore file
├── README.md            # This file
└── iam_risky_policies.json  # Generated report (after running)
```

## 🛡️ Security Considerations

- **API Key Security**: Never commit API keys to version control
- **AWS Permissions**: The tool requires `iam:ListPolicies`, `iam:GetPolicy`, and `iam:GetPolicyVersion` permissions
- **Data Privacy**: Policy data is sent to Google's Gemini API for analysis
- **Rate Limits**: Be aware of API rate limits for both AWS and Google services

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is open source and available under the [MIT License](LICENSE).

## 🐛 Troubleshooting

### Common Issues

1. **AWS Credentials Error**: Ensure AWS CLI is configured or environment variables are set
2. **Gemini API Error**: Verify your API key is valid and has not exceeded rate limits
3. **Permission Denied**: Ensure your AWS user/role has the required IAM permissions

### Debug Mode

Add error handling and logging to debug issues:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 📊 Sample Report

After running the tool, you'll get a detailed JSON report showing:
- Policy names and ARNs
- Specific risky statements
- AI-generated risk explanations
- Actionable recommendations

---

**⚠️ Disclaimer**: This tool is for security assessment purposes. Always review and validate findings before making policy changes in production environments.
